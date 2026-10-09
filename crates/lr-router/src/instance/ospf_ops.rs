//! OSPF-specific `impl DefaultRouter` methods.
//!
//! These methods live in a sibling module so [`super::DefaultRouter`]'s
//! main impl block stays readable. Rust allows `impl Type` blocks in any
//! module within the same crate, and methods in a child module can access
//! private fields of the type — so NO field visibility changes are needed.

use super::*;

impl DefaultRouter {
    /// Flood `lsas` to every OSPF session of `area` except `exclude`
    /// (RFC 2328 §13.3, simplified: no ack/retransmission bookkeeping —
    /// the poll-driven embedder handles transport reliability).
    pub(super) fn ospf_flood(&mut self, area_id: u32, lsas: &[Lsa], exclude: Option<u64>) {
        if lsas.is_empty() {
            return;
        }
        for (handle, state) in self.sessions.iter_mut() {
            let SessionState::Ospf { runtime, conn } = state else {
                continue;
            };
            if runtime.area_id != area_id || exclude == Some(*handle) {
                continue;
            }
            let packet =
                ospf_ls_update(runtime.protocol, runtime.router_id, area_id, lsas.to_vec());
            if let Ok(mut bytes) = runtime.codec.encode_vec(&packet) {
                Self::finalize_ospf_v2_egress(runtime.protocol, &mut bytes);
                conn.put_output(&bytes);
            }
        }
    }

    /// Whether this router currently acts as an OSPF area border router
    /// for `protocol`: attached to the backbone plus at least one other
    /// area, all areas running that version (RFC 2328 §12.4.3 for v2;
    /// RFC 5340 §4.4.3.4 for v3). Stub/NSSA summaries, defaults,
    /// type-7 → type-5 translation and the v3 inter-area/ASBR
    /// summaries all hinge on border-router status.
    pub(super) fn ospf_is_abr_for(&self, protocol: Protocol) -> bool {
        self.ospf_router_id.is_some()
            && self.ospf_areas.len() >= 2
            && self.ospf_areas.contains_key(&0)
            && self.ospf_areas.values().all(|a| a.protocol == protocol)
    }

    /// Whether this router currently acts as an OSPF area border router:
    /// attached to the backbone plus at least one other area, all v2
    /// (RFC 2328 §12.4.3). Stub/NSSA summaries, defaults and type-7 →
    /// type-5 translation all hinge on border-router status.
    pub(super) fn ospf_is_abr(&self) -> bool {
        self.ospf_is_abr_for(Protocol::Ospfv2)
    }

    /// Recompute the OSPF route table after any area LSDB changed:
    /// first re-evaluate the virtual links (RFC 2328 §15 — a link coming
    /// up attaches the backbone and changes border-router status), then
    /// re-run ABR summary origination (§12.4.3) so inter-area knowledge
    /// propagates, refresh the NSSA type-7 → type-5 translations
    /// (RFC 3101 §3.2) and finally rebuild the merged view.
    pub(super) fn ospf_on_lsdb_change(&mut self) -> RuntimeDelta {
        self.ospf_eval_virtual_links();
        self.ospf_summarize_areas();
        self.ospf_translate_nssa();
        self.ospf_recompute()
    }

    /// One area's computed route table: intra-area routes from SPF
    /// (RFC 2328 §16.1) merged with inter-area routes derived from
    /// summary-LSAs (§16.2) and external routes from type-5 LSAs (§16.4)
    /// or, in an NSSA, type-7 LSAs (RFC 3101 §2.5). Intra-area paths win
    /// per prefix, then inter-area, then external (§11) —
    /// `OspfTableEntry::beats` encodes the full order.
    ///
    /// Stub/NSSA areas (`kind`) never see type-5/type-4 LSAs (they are
    /// refused at install time — this filter is a second line of
    /// defence), `no_summary` areas only honour the default type-3
    /// summary, and the NSSA external calculation receives the
    /// border-router default-install rules of RFC 3101 §2.5 step (3).
    pub(super) fn ospf_area_table(
        kind: &OspfAreaType,
        border_router: bool,
        lsdb: &Lsdb,
        spf_result: &spf::SpfResult,
    ) -> BTreeMap<Prefix, OspfTableEntry> {
        let mut table: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
        for r in spf_result
            .stub_routes
            .iter()
            .chain(spf_result.transit_routes.iter())
        {
            // SPF visits vertices in order of increasing distance, so
            // the first entry for a given prefix has the lowest metric.
            // Use `or_insert_with` so a connected stub route (next_hop
            // = None, lowest metric) is NOT overwritten by a via-peer
            // route to the same prefix (next_hop = Some, higher metric).
            // Overwriting would install a gateway route for a directly
            // connected network, which the kernel FIB mirror then uses
            // to replace the connected route — breaking reachability to
            // the gateway itself and cascading ENETUNREACH on every
            // downstream route that points through it.
            table
                .entry(r.prefix)
                .or_insert_with(|| OspfTableEntry::intra(r.metric, r.next_hop));
        }
        for r in spf::summary_routes(lsdb, spf_result) {
            // `no_summary` areas must only ever derive the default from
            // type-3 summaries (RFC 2328 §12.4.3; RFC 3101 §2.7). A /0
            // prefix is necessarily 0.0.0.0/0.
            if kind.no_summary() && r.prefix.prefix_len != 0 {
                continue;
            }
            table
                .entry(r.prefix)
                .or_insert_with(|| OspfTableEntry::inter(r.metric, r.border_router));
        }
        match kind {
            OspfAreaType::Normal => {
                // `external_routes` already resolves §16.4 (6) among
                // competing type-5 candidates per prefix, so at most one
                // external candidate remains — it only fills prefixes
                // without an internal route.
                for r in external_routes(lsdb, spf_result) {
                    table.entry(r.prefix).or_insert_with(|| {
                        OspfTableEntry::external(
                            r.metric,
                            r.metric_type,
                            r.asbr,
                            (r.forwarding_addr != 0)
                                .then(|| IpAddr::V4(r.forwarding_addr.to_be_bytes())),
                            r.internal_cost,
                        )
                    });
                }
            }
            OspfAreaType::Nssa { .. } => {
                // RFC 3101 §2.5: type-7 externals with the same §16.4
                // metric semantics (type-5 and type-7 metrics are
                // directly comparable).
                let opts = NssaCalcOpts {
                    border_router,
                    summaries_suppressed: kind.no_summary(),
                };
                for r in nssa_routes(lsdb, spf_result, opts) {
                    table.entry(r.prefix).or_insert_with(|| {
                        OspfTableEntry::external(
                            r.metric,
                            r.metric_type,
                            r.asbr,
                            (r.forwarding_addr != 0)
                                .then(|| IpAddr::V4(r.forwarding_addr.to_be_bytes())),
                            r.internal_cost,
                        )
                    });
                }
            }
            OspfAreaType::Stub { .. } => {}
        }
        table
    }

    /// Rebuild the merged OSPF route table across all areas and diff it
    /// against the published set. Across areas: intra-area beats
    /// inter-area, then lowest metric, then lowest area ID (areas iterate
    /// in sorted order, so the first entry of a full tie wins —
    /// deterministic).
    pub(super) fn ospf_recompute(&mut self) -> RuntimeDelta {
        let Some(router_id) = self.ospf_router_id else {
            return self.ospf_diff_published(BTreeMap::new());
        };
        let abr = self.ospf_is_abr();
        // Best entry per prefix across areas.
        let mut global: BTreeMap<Prefix, (OspfTableEntry, u32, Protocol)> = BTreeMap::new();
        for (area_id, area) in &self.ospf_areas {
            if area.protocol == Protocol::Ospfv3 {
                // OSPFv3 area (RFC 5340): the intra-area calculation
                // runs over the v3 LSDB — intra-area prefixes plus,
                // with `ospf_srv6_receive` on, the RFC 9513 §5 SRv6
                // locators; then the inter-area summaries (§4.8.3,
                // 0x2003) and AS externals (§4.8.5, 0x4005).
                let spf3 = if self.ospf_v3_extended_lsas {
                    spf::run_spf_v3_extended(&area.lsdb, router_id)
                } else {
                    spf::run_spf_v3(&area.lsdb, router_id)
                };
                let mut table: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
                for r in &spf3.routes {
                    table
                        .entry(r.prefix)
                        .or_insert_with(|| OspfTableEntry::intra_v3(r.metric, r.next_hop));
                }
                if self.ospf_srv6_receive {
                    // RFC 9513 §5: locators of supported algorithms
                    // install as forwarding entries. A prefix
                    // reachability advertisement covering the same
                    // prefix (the Intra-Area-Prefix routes above)
                    // MUST be preferred (§5), so this only fills the
                    // gaps the IAP routes left.
                    for loc in &spf3.locators {
                        if !Self::ospf_srv6_algorithm_supported(loc.algorithm) {
                            continue;
                        }
                        table
                            .entry(loc.prefix)
                            .or_insert_with(|| OspfTableEntry::intra_v3(loc.metric, loc.next_hop));
                    }
                }
                // §4.8.3: inter-area routes from 0x2003 summaries —
                // intra-area paths win per prefix (§16.2 (b)), and
                // `no_summary` areas derive only the default (the same
                // rule the v2 area table applies).
                for r in if self.ospf_v3_extended_lsas {
                    spf::summary_routes_v3_extended(&area.lsdb, &spf3)
                } else {
                    spf::summary_routes_v3(&area.lsdb, &spf3)
                } {
                    if area.kind.no_summary() && r.prefix.prefix_len != 0 {
                        continue;
                    }
                    table.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::Inter {
                            border_router: r.border_router.unwrap_or(0),
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                // §4.8.5: AS externals from 0x4005 — `external_routes_v3`
                // resolves the §16.4 (6) preference among candidates, and
                // the entry only fills prefixes without an internal or
                // inter-area route (§11 path preference).
                for r in if self.ospf_v3_extended_lsas {
                    lr_ospf::external::external_routes_v3_extended(&area.lsdb, &spf3)
                } else {
                    lr_ospf::external::external_routes_v3(&area.lsdb, &spf3)
                } {
                    table.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::External {
                            metric_type: r.metric_type,
                            asbr: r.asbr,
                            forwarding_addr: r.forwarding_addr,
                            internal_cost: r.internal_cost,
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                for (prefix, entry) in table {
                    let better = match global.get(&prefix) {
                        None => true,
                        Some((prev, _, _)) => entry.beats(prev),
                    };
                    if better {
                        global.insert(prefix, (entry, *area_id, Protocol::Ospfv3));
                    }
                }
                continue;
            }
            let spf_result = spf::run_spf(&area.lsdb, router_id);
            let mut table = Self::ospf_area_table(&area.kind, abr, &area.lsdb, &spf_result);
            if self.ospf_sr_receive {
                // RFC 8665 reception: project the area's SR state and
                // attach the resolved labels to the routes they map
                // onto (fail-soft — an LSDB without SR LSAs yields an
                // empty database and changes nothing).
                let srdb = lr_ospf::srdb::SrDatabase::from_lsdb(&area.lsdb);
                Self::ospf_attach_sr_labels(&mut table, &srdb, &spf_result);
            }
            for (prefix, entry) in table {
                let better = match global.get(&prefix) {
                    None => true,
                    Some((prev, _, _)) => entry.beats(prev),
                };
                if better {
                    global.insert(prefix, (entry, *area_id, area.protocol));
                }
            }
        }
        let current: BTreeMap<RouteKey, Route> = global
            .into_iter()
            .map(|(prefix, (entry, area_id, protocol))| {
                // OSPFv3 routes are IPv6 routes: the v3 SPF derives
                // IPv6 prefixes and link-local next hops, so they key
                // into the v6-unicast family (RFC 5340 §3.1 — OSPF for
                // IPv6 installs IPv6 routes).
                let key = if protocol == Protocol::Ospfv3 {
                    RouteKey::new(prefix, NlriFamily::IPV6_UNICAST)
                } else {
                    RouteKey::new(prefix, NlriFamily::IPV4_UNICAST)
                };
                // §16.4: an external route with a forwarding address
                // forwards traffic to that address, not to the ASBR.
                let mut next_hop = match entry.kind {
                    OspfKind::External {
                        forwarding_addr: Some(fa),
                        ..
                    } => Some(fa),
                    _ => entry.next_hop,
                };
                // RFC 8660 head end: an SR-labelled route enters the
                // LSP — the private LrMplsLabelStack attribute carries
                // the label to the kernel mirror (same channel the
                // RFC 8277 BGP-LU routes use), and the next hop is the
                // first hop toward the prefix-SID originator.
                let mut attributes = lr_core::attr::Attributes::new();
                if let (Some(label), Some(nh)) = (entry.label, entry.label_nh) {
                    let stack =
                        lr_mpls::LabelStack::from_labels([lr_mpls::Label::new_value(label)]);
                    let mut attrs = PathAttributes::new();
                    attrs.insert(PathAttribute::new(
                        PathAttrFlags::new().set_optional(true),
                        AttrType::LrMplsLabelStack,
                        stack.encode_4octet(),
                    ));
                    attributes = attrs.into();
                    next_hop = Some(nh);
                }
                let route = Route {
                    key: key.clone(),
                    origin: RouteOrigin {
                        proto: 3, // OSPF adjacency tag
                        peer: u64::from(area_id),
                    },
                    protocol,
                    preference: lr_core::rib::Preference::new(
                        protocol.default_admin_distance(),
                        entry.metric as u32,
                    ),
                    next_hop,
                    attributes,
                    age_ms: 0,
                    path_id: 0,
                    tag: None,
                };
                (key, route)
            })
            .collect();
        self.ospf_diff_published(current)
    }

    /// Attach the RFC 8665 §5 labels an SR database resolves for the
    /// table's prefixes. Only intra-area and inter-area entries are
    /// labelled: their paths follow the prefix-SID originator, while an
    /// external route forwards to the ASBR or the type-5 forwarding
    /// address — a different path than the one the SID encodes. The
    /// label plus its next hop ride the entry (see
    /// [`OspfTableEntry::label`]); the entry kind and metric are
    /// untouched, so route selection is unaffected.
    ///
    /// Prefixes without a direct Prefix-SID advertisement fall back to
    /// the SR Mapping Server's M-flagged ranges (RFC 8665 §4, RFC 8661
    /// §3.2.3): the LSP rides the prefix's *own* path, so the entry
    /// keeps the route's regular next hop and only the label is
    /// attached.
    pub(super) fn ospf_attach_sr_labels(
        table: &mut BTreeMap<Prefix, OspfTableEntry>,
        srdb: &lr_ospf::srdb::SrDatabase,
        spf: &spf::SpfResult,
    ) {
        for (prefix, entry) in table.iter_mut() {
            if !entry.is_intra() && !matches!(entry.kind, OspfKind::Inter { .. }) {
                continue;
            }
            if let Some((label, next_hop)) = srdb.label_for(prefix, spf) {
                entry.label = Some(label);
                entry.label_nh = Some(next_hop);
                continue;
            }
            if let Some(label) = srdb.mapping_label_for(prefix, spf) {
                // RFC 8661 §3.2.2: install the mapping exactly as if
                // the prefix owner had advertised it — the LSP rides
                // the prefix's own path (intra: the SPF route's next
                // hop; inter: the path toward the advertising border
                // router), not the path toward the mapping server.
                let next_hop = match entry.kind {
                    OspfKind::Inter { border_router } => spf
                        .next_hops
                        .get(&spf::VertexId::Router(border_router))
                        .copied(),
                    _ => spf
                        .stub_routes
                        .iter()
                        .chain(&spf.transit_routes)
                        .find(|r| r.prefix == *prefix)
                        .and_then(|r| r.next_hop),
                };
                entry.label = Some(label);
                entry.label_nh = next_hop;
            }
        }
    }

    /// Diff `current` against the published OSPF table and swap it in.
    pub(super) fn ospf_diff_published(
        &mut self,
        current: BTreeMap<RouteKey, Route>,
    ) -> RuntimeDelta {
        let mut delta = RuntimeDelta {
            installed: Vec::new(),
            withdrawn: Vec::new(),
            withdraw_reason: String::new(),
        };
        for (k, r) in &current {
            match self.ospf_published.get(k) {
                Some(prev) if prev == r => {}
                _ => delta.installed.push(r.clone()),
            }
        }
        for k in self.ospf_published.keys() {
            if !current.contains_key(k) {
                delta.withdrawn.push(k.clone());
            }
        }
        self.ospf_published = current;
        delta
    }

    /// ABR summary origination for both protocol planes (RFC 2328
    /// §12.4.3 / RFC 5340 §4.4.3.4): each version's ABR machinery runs
    /// when every attached area speaks it, and its self-originated
    /// summaries are flushed when it does not (fail-closed — e.g. a
    /// mixed v2/v3 router acts as an ABR for neither version).
    pub(super) fn ospf_summarize_areas(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let mut changed = false;
        // OSPFv2 plane: type-3 summaries, type-4 ASBR summaries, the
        // stub/NSSA defaults.
        if self.ospf_is_abr() {
            changed |= self.ospf_summarize_areas_v2(router_id);
        } else {
            // Not a functioning v2 ABR: flush every self-originated
            // summary (type-3) and summary-ASBR (type-4) LSA ...
            changed |= self.ospf_flush_self_lsa_types(router_id, |key| {
                key.ls_type == LsaTypeV2::SummaryIpLsa as u16
                    || key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
            });
            // ... and the ABR-injected NSSA defaults lose their
            // justification too (RFC 3101 §2.4).
            changed |= self.ospf_nssa_defaults();
        }
        // OSPFv3 plane: 0x2003 inter-area-prefix and 0x2004
        // inter-area-router summaries (RFC 5340 §4.4.3.4/§4.4.3.5).
        if self.ospf_is_abr_for(Protocol::Ospfv3) {
            changed |= self.ospf_summarize_areas_v3(router_id);
        } else {
            changed |= self.ospf_flush_self_lsa_types(router_id, |key| {
                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
                    || key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
            });
            self.ospf_v3_summary_lsids.clear();
        }
        changed
    }

    /// OSPFv2 ABR summary origination (RFC 2328 §12.4.3). See
    /// [`Self::ospf_summarize_areas`] for the dispatch rules.
    pub(super) fn ospf_summarize_areas_v2(&mut self, router_id: u32) -> bool {
        // 1. Fresh per-area SPF results and route tables.
        let spf_results: BTreeMap<u32, spf::SpfResult> = self
            .ospf_areas
            .iter()
            .map(|(id, area)| (*id, spf::run_spf(&area.lsdb, router_id)))
            .collect();
        let tables: BTreeMap<u32, BTreeMap<Prefix, OspfTableEntry>> = self
            .ospf_areas
            .iter()
            .map(|(id, area)| {
                (
                    *id,
                    Self::ospf_area_table(
                        &area.kind,
                        true,
                        &area.lsdb,
                        spf_results.get(id).unwrap(),
                    ),
                )
            })
            .collect();
        let backbone = tables.get(&0).cloned().unwrap_or_default();

        // 2. Per-target source sets, then diff against the self-originated
        //    type-3 LSAs already in the target LSDB.
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for (&target, table) in &tables {
            let kind = self
                .ospf_areas
                .get(&target)
                .map(|a| a.kind)
                .unwrap_or(OspfAreaType::Normal);
            // Sources: what the target should learn about the outside.
            let mut sources: BTreeMap<Prefix, u64> = if target == 0 {
                // Backbone: intra-area nets of every non-backbone area.
                let mut s = BTreeMap::new();
                for (id, t) in &tables {
                    if *id == 0 {
                        continue;
                    }
                    for (p, e) in t {
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            } else if kind.no_summary() {
                // Totally-stubby / totally-NSSA target: only the injected
                // default (RFC 2328 §3.6; RFC 3101 §2.7 switches NSSAs to
                // a type-3 default when summaries are suppressed).
                BTreeMap::new()
            } else {
                let mut s = BTreeMap::new();
                // (a) Backbone intra nets.
                for (p, e) in &backbone {
                    if e.is_intra() {
                        s.insert(*p, e.metric);
                    }
                }
                // (b) Inter-area routes other ABRs put into the backbone.
                //     External routes (§16.4) are never summarized — they
                //     travel as type-5 LSAs at AS scope.
                for (p, e) in &backbone {
                    if !e.is_intra()
                        && !e.is_own_inter(router_id)
                        && !matches!(e.kind, OspfKind::External { .. })
                    {
                        s.insert(*p, e.metric);
                    }
                }
                // (c) Intra nets of the remaining non-backbone areas — the
                //     mirror of this router's own backbone summaries.
                for (id, t) in &tables {
                    if *id == 0 || *id == target {
                        continue;
                    }
                    for (p, e) in t {
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            };
            // Border-router default into stub/NSSA targets (RFC 2328
            // §3.6; RFC 3101 §2.7): a type-3 summary default with the
            // configured metric. NSSAs with summaries imported carry the
            // default as a type-7 LSA instead (see `ospf_nssa_defaults`).
            if target != 0 {
                if let Some(metric) = kind.default_metric() {
                    if !kind.is_nssa() || kind.no_summary() {
                        sources.insert(Prefix::new_v4([0, 0, 0, 0], 0), u64::from(metric));
                    }
                }
            }
            // Loop guard: never summarize the target's own intra nets back
            // into the target (a stub area never carries an intra 0/0, so
            // the injected default survives the guard).
            for (p, e) in table {
                if e.is_intra() {
                    sources.remove(p);
                }
            }

            // 3. Existing self-originated summaries, keyed by LS-ID.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == LsaTypeV2::SummaryIpLsa as u16
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let mut to_originate: Vec<Lsa> = Vec::new();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            for (prefix, metric) in &sources {
                let dest = SummaryDestination::new(*prefix, *metric as u32);
                let mask = prefix_len_to_mask(prefix.prefix_len);
                let network = match prefix.addr {
                    lr_core::addr::IpAddr::V4(o) => u32::from_be_bytes(o) & mask,
                    lr_core::addr::IpAddr::V6(_) => continue,
                };
                used_lsids.insert(network);
                let prev = existing.get(&network);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_summary_lsa_body(&lsa.body).is_some_and(|body| {
                        body.network_mask == mask && body.tos0_metric() == Some(dest.metric)
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_summary_lsa(router_id, &dest, prev_seq) {
                    to_originate.push(lsa);
                }
            }
            // 4. Flush summaries whose destination disappeared.
            let mut to_flush: Vec<Lsa> = Vec::new();
            for (lsid, lsa) in &existing {
                if !used_lsids.contains(lsid) {
                    if let Some(flush) = flush_summary_lsa(lsa) {
                        to_flush.push(flush);
                    }
                }
            }

            if to_originate.is_empty() && to_flush.is_empty() {
                continue;
            }
            // 5. Install into the target LSDB and queue for flooding.
            //    Origination replaces (seq+1); MaxAge flush purges.
            let mut flooded = Vec::with_capacity(to_originate.len() + to_flush.len());
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for lsa in to_originate.into_iter().chain(to_flush) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        flooded.push(lsa);
                        changed = true;
                    }
                }
            }
            if !flooded.is_empty() {
                floods.push((target, flooded));
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        // RFC 3101 §2.4: border-router type-7 defaults for NSSAs that
        // still import summaries.
        let nssa_default_changed = self.ospf_nssa_defaults();
        // §12.4.3: summary-ASBR (type-4) origination for ASBRs that this
        // ABR can reach but the target area cannot (see the helper).
        self.ospf_summarize_asbrs(router_id, &spf_results) | changed | nssa_default_changed
    }

    /// OSPFv3 ABR summary origination (RFC 5340 §4.4.3.4 and
    /// §4.4.3.5) — the v3 mirror of [`Self::ospf_summarize_areas_v2`]:
    ///
    /// - 0x2003 inter-area-prefix-LSAs follow the v2 type-3 source
    ///   rules (into the backbone: every non-backbone area's
    ///   intra-area prefixes; into a non-backbone area: the backbone's
    ///   intra-area prefixes plus the inter-area routes other ABRs
    ///   summarized there; the target's own intra-area prefixes are
    ///   never summarized back; stubby targets receive the configured
    ///   default instead — a zero-length prefix, the v3 default form).
    /// - 0x2004 inter-area-router-LSAs advertise ASBRs (the
    ///   advertisers of 0x4005 LSAs) that are reachable through other
    ///   areas but not intra-area in the target, at the ABR's own cost
    ///   — LS ID = the destination router ID.
    ///
    /// The 0x2003 LS ID carries no addressing semantics (§4.4.3.4), so
    /// each prefix keeps a stable per-area LS ID: the previous
    /// instance's LS ID is reused when one exists, else the next free
    /// ID is allocated (FRR `ospf6_new_ls_id` parity).
    pub(super) fn ospf_summarize_areas_v3(&mut self, router_id: u32) -> bool {
        // 1. Fresh per-area v3 SPF results and route tables (the same
        //    merge the recompute uses: intra + inter, externals
        //    excluded from the sources).
        let spf_results: BTreeMap<u32, spf::SpfResultV3> = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, area)| {
                (
                    *id,
                    if self.ospf_v3_extended_lsas {
                        spf::run_spf_v3_extended(&area.lsdb, router_id)
                    } else {
                        spf::run_spf_v3(&area.lsdb, router_id)
                    },
                )
            })
            .collect();
        let tables: BTreeMap<u32, BTreeMap<Prefix, OspfTableEntry>> = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, area)| {
                let spf3 = spf_results.get(id).expect("v3 spf result");
                let mut t: BTreeMap<Prefix, OspfTableEntry> = BTreeMap::new();
                for r in &spf3.routes {
                    t.entry(r.prefix)
                        .or_insert_with(|| OspfTableEntry::intra_v3(r.metric, r.next_hop));
                }
                for r in if self.ospf_v3_extended_lsas {
                    spf::summary_routes_v3_extended(&area.lsdb, spf3)
                } else {
                    spf::summary_routes_v3(&area.lsdb, spf3)
                } {
                    if area.kind.no_summary() && r.prefix.prefix_len != 0 {
                        continue;
                    }
                    t.entry(r.prefix).or_insert_with(|| OspfTableEntry {
                        metric: r.metric,
                        kind: OspfKind::Inter {
                            border_router: r.border_router.unwrap_or(0),
                        },
                        label: None,
                        label_nh: None,
                        next_hop: r.next_hop,
                    });
                }
                (*id, t)
            })
            .collect();
        let backbone = tables.get(&0).cloned().unwrap_or_default();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for &target in &areas {
            let Some(kind) = self
                .ospf_areas
                .get(&target)
                .filter(|a| a.protocol == Protocol::Ospfv3)
                .map(|a| a.kind)
            else {
                continue;
            };
            // Sources: what the target should learn about the outside.
            let mut sources: BTreeMap<Prefix, u64> = if target == 0 {
                let mut s = BTreeMap::new();
                for (id, t) in &tables {
                    if *id == 0 {
                        continue;
                    }
                    for (p, e) in t {
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            } else if kind.no_summary() {
                BTreeMap::new()
            } else {
                let mut s = BTreeMap::new();
                for (p, e) in &backbone {
                    if e.is_intra() {
                        s.insert(*p, e.metric);
                    }
                }
                for (p, e) in &backbone {
                    if !e.is_intra()
                        && !e.is_own_inter(router_id)
                        && !matches!(e.kind, OspfKind::External { .. })
                    {
                        s.insert(*p, e.metric);
                    }
                }
                for (id, t) in &tables {
                    if *id == 0 || *id == target {
                        continue;
                    }
                    for (p, e) in t {
                        if e.is_intra() {
                            s.entry(*p)
                                .and_modify(|m: &mut u64| *m = (*m).min(e.metric))
                                .or_insert(e.metric);
                        }
                    }
                }
                s
            };
            // Stubby v3 targets receive the border-router default (the
            // zero-length prefix form of §4.4.3.4).
            if target != 0 {
                if let Some(metric) = kind.default_metric() {
                    if kind.is_stub() {
                        sources.insert(Prefix::new_v6([0u8; 16], 0), u64::from(metric));
                    }
                }
            }
            // Loop guard: never summarize the target's own intra-area
            // prefixes back into the target.
            if let Some(table) = tables.get(&target) {
                for (p, e) in table {
                    if e.is_intra() {
                        sources.remove(p);
                    }
                }
            }

            // Existing self-originated 0x2003s, keyed by LS ID.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            // Stable LS ID allocation: the router's mapping first,
            // else a previous instance advertising the same prefix,
            // else the lowest free ID.
            let area_map = self.ospf_v3_summary_lsids.entry(target).or_default();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            let mut to_originate: Vec<Lsa> = Vec::new();
            for (prefix, metric) in &sources {
                let ls_id = match area_map.get(prefix) {
                    Some(&id) => id,
                    None => {
                        let reused = existing.iter().find_map(|(id, lsa)| {
                            lr_ospf::lsa::decode_v3_inter_area_prefix_body(&lsa.body)
                                .filter(|b| b.to_prefix().as_ref() == Some(prefix))
                                .map(|_| *id)
                        });
                        let id = reused.unwrap_or_else(|| {
                            (1u32..)
                                .find(|id| !existing.contains_key(id) && !used_lsids.contains(id))
                                .unwrap_or(0)
                        });
                        area_map.insert(*prefix, id);
                        id
                    }
                };
                used_lsids.insert(ls_id);
                let dest = SummaryDestination::new(*prefix, *metric as u32);
                let prev = existing.get(&ls_id);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_v3_inter_area_prefix_body(&lsa.body).is_some_and(|b| {
                        b.metric == dest.metric
                            && b.prefix_len == dest.prefix.prefix_len
                            && b.to_prefix().as_ref() == Some(prefix)
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) =
                    originate_v3_inter_area_prefix_lsa(router_id, ls_id, &dest, prev_seq)
                {
                    to_originate.push(lsa);
                }
            }
            // Flush summaries whose destination disappeared.
            let mut to_flush: Vec<Lsa> = Vec::new();
            for (lsid, lsa) in &existing {
                if !used_lsids.contains(lsid) {
                    if let Some(flush) = flush_summary_lsa(lsa) {
                        to_flush.push(flush);
                    }
                }
            }

            if to_originate.is_empty() && to_flush.is_empty() {
                continue;
            }
            let mut flooded = Vec::with_capacity(to_originate.len() + to_flush.len());
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for lsa in to_originate.into_iter().chain(to_flush) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        flooded.push(lsa);
                        changed = true;
                    }
                }
            }
            if !flooded.is_empty() {
                floods.push((target, flooded));
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        // §4.4.3.5: 0x2004 inter-area-router summaries for ASBRs this
        // ABR can reach but the target area cannot.
        self.ospf_summarize_asbrs_v3(router_id, &spf_results) | changed
    }

    /// RFC 5340 §4.4.3.5 (the v3 type-4): for every ASBR — the
    /// advertisers of the 0x4005 LSAs present in the v3 LSDBs —
    /// originate into each attached v3 area an inter-area-router-LSA
    /// when the ASBR is intra-area reachable through one of the
    /// router's other areas but not through the target. The advertised
    /// metric is the ABR's own cost to the ASBR; the Options field
    /// mirrors the destination's Router-LSA options (§4.4.3.5); the LS
    /// ID is the destination router ID. Stale self-originated 0x2004s
    /// whose ASBR lost reachability are flushed.
    pub(super) fn ospf_summarize_asbrs_v3(
        &mut self,
        router_id: u32,
        spf_results: &BTreeMap<u32, spf::SpfResultV3>,
    ) -> bool {
        // AS-scope 0x4005s are installed in every v3 area; derive the
        // ASBR set from whichever v3 area has an LSDB (lowest ID).
        let source_area = self
            .ospf_areas
            .iter()
            .filter(|(_, area)| area.protocol == Protocol::Ospfv3)
            .map(|(id, _)| *id)
            .min();
        let Some(source_area) = source_area else {
            return false;
        };
        let Some(source) = self.ospf_areas.get(&source_area) else {
            return false;
        };
        let asbrs: BTreeSet<u32> = source
            .lsdb
            .iter()
            .filter(|(key, _)| {
                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
                    && key.advertising_router != router_id
            })
            .map(|(key, _)| key.advertising_router)
            .collect();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            let Some(target_kind) = self.ospf_areas.get(&target).map(|a| a.kind) else {
                continue;
            };
            let is_v3 = self
                .ospf_areas
                .get(&target)
                .is_some_and(|a| a.protocol == Protocol::Ospfv3);
            // Stale self-originated 0x2004s: flushed everywhere when the
            // target left the v3 plane or went stubby.
            if !is_v3 || target_kind.is_stubby() {
                let flushes: Vec<Lsa> = self
                    .ospf_areas
                    .get(&target)
                    .map(|area| {
                        area.lsdb
                            .iter()
                            .filter(|(key, _)| {
                                key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
                                    && key.advertising_router == router_id
                            })
                            .filter_map(|(_, entry)| flush_summary_lsa(&entry.lsa))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(area) = self.ospf_areas.get_mut(&target) {
                    for flush in flushes {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
                continue;
            }
            // Existing self-originated 0x2004s, keyed by destination
            // (the LS ID is the destination router ID).
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let mut to_originate: Vec<Lsa> = Vec::new();
            let mut to_flush: Vec<Lsa> = Vec::new();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            for &asbr in &asbrs {
                if asbr == router_id {
                    continue;
                }
                let intra_here = spf_results
                    .get(&target)
                    .is_some_and(|r| r.vertices.contains_key(&spf::V3VertexId::Router(asbr)));
                if intra_here {
                    continue; // the target reaches the ASBR itself
                }
                let best: Option<(u64, u32)> = spf_results
                    .iter()
                    .filter(|(id, _)| **id != target)
                    .filter_map(|(_, r)| {
                        let d = r.vertices.get(&spf::V3VertexId::Router(asbr)).copied()?;
                        // The options the destination's own Router-LSA
                        // advertises (§4.4.3.5).
                        let opts = r.router_options.get(&asbr).copied().unwrap_or(0);
                        Some((d, opts))
                    })
                    .min_by_key(|(d, _)| *d);
                let Some((cost, options)) = best else {
                    continue; // unreachable through us
                };
                used_lsids.insert(asbr);
                let prev = existing.get(&asbr);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::v3::V3InterAreaRouterBody::decode(&lsa.body).is_some_and(|b| {
                        b.metric == cost.min(0x00ff_fffe) as u32 && b.options == options
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_v3_inter_area_router_lsa(
                    router_id,
                    asbr,
                    options,
                    asbr,
                    cost.min(0x00ff_fffe) as u32,
                    prev_seq,
                ) {
                    to_originate.push(lsa);
                }
            }
            for (lsid, lsa) in &existing {
                if !used_lsids.contains(lsid) {
                    if let Some(flush) = flush_summary_lsa(lsa) {
                        to_flush.push(flush);
                    }
                }
            }
            if to_originate.is_empty() && to_flush.is_empty() {
                continue;
            }
            let mut flooded = Vec::with_capacity(to_originate.len() + to_flush.len());
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for lsa in to_originate.into_iter().chain(to_flush) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        flooded.push(lsa);
                        changed = true;
                    }
                }
            }
            if !flooded.is_empty() {
                floods.push((target, flooded));
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// MaxAge-flush every self-originated LSA whose key satisfies `pred`
    /// across all areas (RFC 2328 §14.1). Returns whether any LSDB
    /// changed; flushes are flooded on their area.
    pub(super) fn ospf_flush_self_lsa_types(
        &mut self,
        router_id: u32,
        pred: impl Fn(&lr_ospf::lsa::LsaKey) -> bool,
    ) -> bool {
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            let mut flushes = Vec::new();
            if let Some(area) = self.ospf_areas.get(&target) {
                for (key, entry) in area.lsdb.iter() {
                    if pred(key) && key.advertising_router == router_id {
                        if let Some(flush) = flush_summary_lsa(&entry.lsa) {
                            flushes.push(flush);
                        }
                    }
                }
            }
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for flush in flushes {
                    if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                        floods.push((target, vec![flush]));
                        changed = true;
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// RFC 3101 §2.4/§2.7: keep the border-router type-7 default
    /// (`0.0.0.0/0`, P-bit clear, zero forwarding address) in sync in
    /// every attached NSSA that imports summaries. Defaults for
    /// `no_summary` NSSAs and for non-ABR routers are flushed. A
    /// redistributed default (`ospf_redistribute` of `0.0.0.0/0`) takes
    /// precedence and suppresses the injected one. Returns whether any
    /// LSDB changed.
    pub(super) fn ospf_nssa_defaults(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_is_abr();
        let redistributed_default = self.ospf_externals.contains_key(&0);
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            // One immutable pass: existing self type-7 default + policy.
            let Some((existing, desired, default_metric)) =
                self.ospf_areas.get(&target).and_then(|area| {
                    if area.protocol != Protocol::Ospfv2 {
                        return None;
                    }
                    let existing = area
                        .lsdb
                        .iter()
                        .find(|(key, _)| {
                            key.ls_type == LsaTypeV2::NssaExternalLsa as u16
                                && key.link_state_id == 0
                                && key.advertising_router == router_id
                        })
                        .map(|(_, entry)| entry.lsa.clone());
                    let desired = abr
                        && area.kind.is_nssa()
                        && !area.kind.no_summary()
                        && !redistributed_default;
                    Some((existing, desired, area.kind.default_metric().unwrap_or(1)))
                })
            else {
                continue;
            };
            if desired {
                let unchanged = existing.as_ref().is_some_and(|lsa| {
                    lr_ospf::lsa::decode_as_external_body(&lsa.body)
                        .is_some_and(|body| body.metric_value() == default_metric)
                });
                if unchanged {
                    continue;
                }
                let prev_seq = existing.as_ref().map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_nssa_default_lsa(
                    router_id,
                    &NssaDefault::new(default_metric),
                    prev_seq,
                ) {
                    if let Some(area) = self.ospf_areas.get_mut(&target) {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            floods.push((target, vec![lsa]));
                            changed = true;
                        }
                    }
                }
            } else if let Some(lsa) = existing {
                if let Some(flush) = flush_nssa_lsa(&lsa) {
                    if let Some(area) = self.ospf_areas.get_mut(&target) {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// RFC 2328 §12.4.3 (type-4): for every ASBR — the advertisers of the
    /// type-5 LSAs present in the LSDB, which are synchronized across
    /// areas at AS scope — originate into each attached area a
    /// summary-ASBR-LSA when the ASBR is intra-area reachable through one
    /// of the router's other areas but not through the target. The
    /// advertised metric is the ABR's own cost to the ASBR. Existing
    /// self-originated type-4s whose ASBR lost reachability are flushed.
    /// Stub/NSSA targets never receive type-4s (RFC 2328 §3.6, RFC 3101
    /// §2.1 — no type-5s live there, so ASBR locations are meaningless);
    /// stale ones are flushed.
    pub(super) fn ospf_summarize_asbrs(
        &mut self,
        router_id: u32,
        spf_results: &BTreeMap<u32, spf::SpfResult>,
    ) -> bool {
        // AS-scope type-5s are installed in every area; derive the ASBR
        // set from whichever area has an LSDB (backbone preferred).
        let source_area = self.ospf_areas.keys().copied().min().unwrap_or_default();
        let Some(source) = self.ospf_areas.get(&source_area) else {
            return false;
        };
        let asbrs: BTreeSet<u32> = source
            .lsdb
            .iter()
            .filter(|(key, _)| key.ls_type == LsaTypeV2::AsExternalLsa as u16)
            .map(|(key, _)| key.advertising_router)
            .collect();

        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
        for target in areas {
            // Stub/NSSA areas refuse type-4s — flush any stale ones and
            // move on.
            if self
                .ospf_areas
                .get(&target)
                .is_some_and(|area| area.kind.is_stubby())
            {
                let flushes: Vec<Lsa> = self
                    .ospf_areas
                    .get(&target)
                    .map(|area| {
                        area.lsdb
                            .iter()
                            .filter(|(key, _)| {
                                key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
                                    && key.advertising_router == router_id
                            })
                            .filter_map(|(_, entry)| flush_summary_lsa(&entry.lsa))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(area) = self.ospf_areas.get_mut(&target) {
                    for flush in flushes {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((target, vec![flush]));
                            changed = true;
                        }
                    }
                }
                continue;
            }
            // Existing self-originated type-4s, keyed by ASBR.
            let existing: BTreeMap<u32, Lsa> = self
                .ospf_areas
                .get(&target)
                .map(|area| {
                    area.lsdb
                        .iter()
                        .filter(|(key, _)| {
                            key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
                                && key.advertising_router == router_id
                        })
                        .map(|(key, entry)| (key.link_state_id, entry.lsa.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let mut to_originate: Vec<Lsa> = Vec::new();
            let mut to_flush: Vec<Lsa> = Vec::new();
            let mut used_lsids: BTreeSet<u32> = BTreeSet::new();
            for &asbr in &asbrs {
                if asbr == router_id {
                    continue; // our own ASBR location is intra-area wherever we attach
                }
                let intra_here = spf_results
                    .get(&target)
                    .is_some_and(|r| r.vertices.contains_key(&spf::VertexId::Router(asbr)));
                if intra_here {
                    continue; // no type-4 needed
                }
                // The ABR's best cost to the ASBR across its other areas.
                let best: Option<u64> = spf_results
                    .iter()
                    .filter(|(id, _)| **id != target)
                    .filter_map(|(_, r)| r.vertices.get(&spf::VertexId::Router(asbr)))
                    .copied()
                    .min();
                let Some(cost) = best else {
                    continue; // unreachable through us — nothing to advertise
                };
                let dest =
                    lr_ospf::external::AsbrDestination::new(asbr, cost.min(0x00ff_fffe) as u32);
                used_lsids.insert(asbr);
                let prev = existing.get(&asbr);
                let unchanged = prev.is_some_and(|lsa| {
                    lr_ospf::lsa::decode_summary_lsa_body(&lsa.body)
                        .is_some_and(|b| b.tos0_metric() == Some(dest.metric))
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_summary_asbr_lsa(router_id, &dest, prev_seq) {
                    to_originate.push(lsa);
                }
            }
            // Flush type-4s whose ASBR no longer needs advertising.
            for (lsid, lsa) in &existing {
                if !used_lsids.contains(lsid) {
                    if let Some(flush) = flush_summary_lsa(lsa) {
                        to_flush.push(flush);
                    }
                }
            }
            if to_originate.is_empty() && to_flush.is_empty() {
                continue;
            }
            let mut flooded = Vec::with_capacity(to_originate.len() + to_flush.len());
            if let Some(area) = self.ospf_areas.get_mut(&target) {
                for lsa in to_originate.into_iter().chain(to_flush) {
                    if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                        flooded.push(lsa);
                        changed = true;
                    }
                }
            }
            if !flooded.is_empty() {
                floods.push((target, flooded));
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }

    /// RFC 3101 §3.2: refresh the type-7 → type-5 translations this router
    /// maintains as a border router of its NSSAs.
    ///
    /// For every installed type-7 LSA in an attached NSSA that (a) is not
    /// the default, (b) carries the P-bit and (c) has a non-zero
    /// forwarding address (§3.2 step (1)), the elected translator
    /// (§3.1: highest router ID among the area's B-bit routers, Nt-bit
    /// wins) originates a type-5 copy — same network, mask, metric type,
    /// metric, forwarding address and tag; itself as advertising router —
    /// into every attached *regular* area (AS scope). Translations whose
    /// source disappeared, lost its P-bit or forwarding address, or whose
    /// translator role was lost are MaxAge-flushed. A locally redistributed
    /// network with the same link-state ID suppresses translation (the
    /// locally sourced type-5 wins, §3.2 note) and shields its LSA from
    /// the flush.
    ///
    /// Returns whether any LSDB changed.
    pub(super) fn ospf_translate_nssa(&mut self) -> bool {
        let Some(router_id) = self.ospf_router_id else {
            return false;
        };
        let abr = self.ospf_is_abr();
        // Desired translations keyed by their source type-7.
        let mut desired: BTreeMap<(u32, u32, u32), ExternalDestination> = BTreeMap::new();
        if abr {
            for (area_id, area) in &self.ospf_areas {
                if !area.kind.is_nssa() || area.protocol != Protocol::Ospfv2 {
                    continue;
                }
                if !is_elected_translator(&area.lsdb, router_id) {
                    continue; // §3.1: another border router translates
                }
                for (key, entry) in area.lsdb.iter() {
                    if key.ls_type != LsaTypeV2::NssaExternalLsa as u16 {
                        continue;
                    }
                    let Some(body) = lr_ospf::lsa::decode_as_external_body(&entry.lsa.body) else {
                        continue;
                    };
                    // §3.2 step (1): defaults, P-bit-clear LSAs and
                    // zero-forwarding-address LSAs are not translated.
                    if entry.lsa.header.options & N_P_BIT == 0
                        || body.forwarding_addr == 0
                        || body.network_mask == 0
                    {
                        continue;
                    }
                    // Locally sourced type-5s are never supplanted.
                    if self.ospf_externals.contains_key(&key.link_state_id) {
                        continue;
                    }
                    let prefix_len = lr_ospf::lsa::mask_to_prefix_len(body.network_mask);
                    let network = entry.lsa.header.link_state_id & body.network_mask;
                    let dest = ExternalDestination {
                        prefix: Prefix::new_v4(network.to_be_bytes(), prefix_len),
                        metric: body.metric_value(),
                        metric_type: ExternalMetricType::from_e_bit(body.external_type2()),
                        forwarding_addr: body.forwarding_addr,
                        route_tag: body.route_tag,
                        p_bit: false, // type-5s carry no P-bit
                    };
                    desired.insert((*area_id, key.link_state_id, key.advertising_router), dest);
                }
            }
        }
        // Track + flush bookkeeping for previously maintained translations.
        let stale: Vec<(u32, u32, u32)> = self
            .ospf_translations
            .iter()
            .filter(|k| !desired.contains_key(*k))
            .copied()
            .collect();
        let mut changed = false;
        let mut floods: Vec<(u32, Vec<Lsa>)> = Vec::new();
        for key in stale {
            self.ospf_translations.remove(&key);
            // MaxAge-flush the self-originated type-5 copy of `key` from
            // every regular area (locally sourced type-5s are shielded).
            if self.ospf_externals.contains_key(&key.1) {
                continue;
            }
            let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
            for area_id in areas {
                let flush = self.ospf_areas.get(&area_id).and_then(|area| {
                    if area.kind.is_stubby() || area.protocol != Protocol::Ospfv2 {
                        return None;
                    }
                    area.lsdb
                        .iter()
                        .find(|(k, _)| {
                            k.ls_type == LsaTypeV2::AsExternalLsa as u16
                                && k.advertising_router == router_id
                                && k.link_state_id == key.1
                        })
                        .and_then(|(_, entry)| flush_external_lsa(&entry.lsa))
                });
                if let Some(flush) = flush {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(flush.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![flush]));
                            changed = true;
                        }
                    }
                }
            }
        }
        // Ensure every desired translation exists (unchanged) in every
        // regular area.
        for (key, dest) in &desired {
            self.ospf_translations.insert(*key);
            let areas: Vec<u32> = self.ospf_areas.keys().copied().collect();
            for area_id in areas {
                if !self
                    .ospf_areas
                    .get(&area_id)
                    .is_some_and(|a| !a.kind.is_stubby() && a.protocol == Protocol::Ospfv2)
                {
                    continue;
                }
                let prev = self.ospf_areas.get(&area_id).and_then(|area| {
                    area.lsdb
                        .iter()
                        .find(|(k, _)| {
                            k.ls_type == LsaTypeV2::AsExternalLsa as u16
                                && k.advertising_router == router_id
                                && k.link_state_id == key.1
                        })
                        .map(|(_, entry)| entry.lsa.clone())
                });
                let unchanged = prev.as_ref().is_some_and(|lsa| {
                    lr_ospf::lsa::decode_as_external_body(&lsa.body).is_some_and(|body| {
                        body.network_mask == prefix_len_to_mask(dest.prefix.prefix_len)
                            && body.external_type2() == dest.metric_type.e_bit()
                            && body.metric_value() == dest.metric
                            && body.forwarding_addr == dest.forwarding_addr
                            && body.route_tag == dest.route_tag
                    })
                });
                if unchanged {
                    continue;
                }
                let prev_seq = prev.as_ref().map(|lsa| lsa.header.ls_sequence_number);
                if let Some(lsa) = originate_external_lsa(router_id, dest, prev_seq) {
                    if let Some(area) = self.ospf_areas.get_mut(&area_id) {
                        if area.lsdb.install(lsa.clone(), self.now_ms).changed() {
                            floods.push((area_id, vec![lsa]));
                            changed = true;
                        }
                    }
                }
            }
        }
        for (area_id, lsas) in floods {
            self.ospf_flood(area_id, &lsas, None);
        }
        changed
    }
}
