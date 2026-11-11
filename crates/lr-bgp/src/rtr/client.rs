//! Transport-agnostic RTR client state machine (RFC 8210 §6-§8),
//! driving the [`super::pdu`] codec.
//!
//! The embedder owns the TCP connection, the clock and the live
//! [`crate::roa::RoaTable`]; [`RtrClient`] owns the protocol:
//!
//! * **Connect** — [`RtrClient::on_connect`] returns the query to
//!   send: a Reset Query when the client holds no session (§8.1), a
//!   Serial Query carrying the remembered `(session, serial)` when
//!   it does.
//! * **Receive** — [`RtrClient::on_pdu`] consumes one decoded PDU
//!   and returns a [`ClientStep`]: bytes to transmit (a query, an
//!   Error Report), whether to drop the session, and — at End of
//!   Data — the atomic ROA deltas of the completed sync.
//! * **Time** — [`RtrClient::poll`] applies the §6 timing rules:
//!   refresh polls while synced, data-expiry reporting once the
//!   expire interval passes without a successful sync.
//!
//! # ROA deltas are atomic per sync
//!
//! Prefix PDUs accumulate in a per-sync batch; the deltas the
//! [`ClientStep`] carries at End of Data are the *diff* between the
//! previous and the new authoritative record sets. The embedder
//! never observes a half-applied database: one sync = one atomic
//! delta batch (or one [`RtrClient::snapshot`] swap). This also
//! coalesces the cache-side churn the protocol allows (multiple
//! changes to one record inside a single serial window, §5.3),
//! duplicates (§5.6 "Duplicate Announcement Received" — logged, not
//! fatal here) and unknown withdrawals (§12 code 6 — logged and
//! diffed to a no-op, BIRD's lenient channel semantics).
//!
//! # Version negotiation (§7)
//!
//! The client starts at [`RTR_VERSION_MAX`]. Until the first
//! completed sync, any PDU received at a lower known version
//! downgrades the session to it (the same first-PDU rule BIRD's
//! `rpki_check_pdu` applies). Serial Notify PDUs are ignored during
//! the startup period regardless of their version (§7).

use std::collections::{BTreeSet, HashSet};

use lr_core::addr::Asn;

use super::pdu::{encode, RtrErrorCode, RtrPdu, RTR_VERSION_MAX};
use crate::roa::RoaEntry;

/// Default refresh interval (RFC 8210 §6: "reasonable default ... an
/// hour"); v0 End-of-Data carries no intervals, so these stand in.
pub const DEFAULT_REFRESH_INTERVAL: u32 = 3600;
/// Default retry interval (§6: "reasonable default ... ten minutes").
pub const DEFAULT_RETRY_INTERVAL: u32 = 600;
/// Default expire interval (§6: "an hour or so" — one hour).
pub const DEFAULT_EXPIRE_INTERVAL: u32 = 7200;

/// Where the client sits in the §8 conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// A Reset Query is in flight (no session, or one being rebuilt).
    AwaitingReset,
    /// A Serial Query is in flight.
    AwaitingSerial,
    /// A Cache Response opened a batch; payload PDUs until EoD.
    ReceivingPayload,
    /// The last sync completed; polling on the refresh timer.
    Synced,
}

/// One ROA record delta at a completed sync: `announce = true` adds
/// the entry to the authoritative set, `announce = false` removes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoaDelta {
    pub announce: bool,
    pub entry: RoaEntry,
}

/// One BGPsec Router Key (RFC 8210 §5.10) the cache vouches for.
///
/// The wire identity of a Router Key is `(ski, asn)` — §5.10 names
/// the SKI as "the 20-byte Subject Key Identifier" and scopes the key
/// by AS. Equality and hashing cover only those two fields, so two
/// PDUs for the same `(ski, asn)` — an announcement and a re-announcement
/// with a different SPKI, or an announcement and a withdrawal — collapse
/// onto one entry in the client's [`HashSet`]. The [`Vec`] SPKI the
/// cache attests is carried as data: a re-announcement with a different
/// SPKI replaces the prior attestation in the batch, and the diff at
/// End of Data surfaces the SPKI change as a withdraw + announce pair
/// (see [`diff_router_keys`]).
#[derive(Debug, Clone)]
pub struct RouterKeyEntry {
    /// RFC 8210 §5.10: the 20-byte SHA-1 hash of the SPKI. The cache
    /// identifies the key by this hash; the client treats it as the
    /// primary identity inside one ASN.
    pub ski: [u8; 20],
    /// The AS number the router key is valid for. RFC 8210 §5.10
    /// scopes a key by `(ski, asn)`; two keys with the same SKI for
    /// different ASNs are distinct records.
    pub asn: u32,
    /// The full DER `subjectPublicKeyInfo` (tag + length + value). The
    /// client does not parse the SPKI — it stores the blob verbatim
    /// and surfaces it on the delta so an embedder that does
    /// BGPsec validation (RFC 8210 §5.10 references the RPKI
    /// certification path) can use the exact bytes the cache attested.
    pub subject_public_key_info: Vec<u8>,
}

impl PartialEq for RouterKeyEntry {
    fn eq(&self, other: &Self) -> bool {
        self.ski == other.ski && self.asn == other.asn
    }
}

impl Eq for RouterKeyEntry {}

impl std::hash::Hash for RouterKeyEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ski.hash(state);
        self.asn.hash(state);
    }
}

/// One ASPA record (RFC 8210 §5.11, SIDROPS ASPA profile) the cache
/// vouches for.
///
/// The wire identity of an ASPA record is the customer ASN — §5.11:
/// "A withdrawal deletes the entire ASPA object for the customer
/// ASN." Equality and hashing cover only `customer_asn`, so two PDUs
/// for the same customer collapse onto one entry in the client's
/// [`HashSet`]. The provider set is carried as data: a re-announcement
/// with a different provider set replaces the prior attestation in
/// the batch, and the diff at End of Data surfaces the change as a
/// withdraw + announce pair (see [`diff_aspa_records`]). The provider
/// set is canonicalised into a [`BTreeSet`] so two announcements that
/// list the same providers in different wire order compare equal
/// (RFC 8210 §5.11 does not pin a wire order; the set is what matters
/// semantically).
#[derive(Debug, Clone)]
pub struct AspaEntry {
    /// The customer AS the providers are attested for. The wire
    /// identity of an ASPA record.
    pub customer_asn: u32,
    /// The set of provider ASNs the cache attests for
    /// `customer_asn`. Stored as a [`BTreeSet`] so two PDUs that list
    /// the same providers in different order compare equal.
    pub providers: BTreeSet<u32>,
}

impl PartialEq for AspaEntry {
    fn eq(&self, other: &Self) -> bool {
        self.customer_asn == other.customer_asn
    }
}

impl Eq for AspaEntry {}

impl std::hash::Hash for AspaEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.customer_asn.hash(state);
    }
}

/// One Router Key delta at a completed sync: `announce = true` adds
/// the entry to the authoritative set, `announce = false` removes it.
/// Mirrors [`RoaDelta`] for the §5.10 Router Key PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterKeyDelta {
    pub announce: bool,
    pub entry: RouterKeyEntry,
}

/// One ASPA delta at a completed sync: `announce = true` adds the
/// entry to the authoritative set, `announce = false` removes it.
/// Mirrors [`RoaDelta`] for the §5.11 ASPA PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AspaDelta {
    pub announce: bool,
    pub entry: AspaEntry,
}

/// What the embedder should do after one protocol step.
#[derive(Debug, Default, Clone)]
pub struct ClientStep {
    /// Wire bytes to transmit (zero or more complete PDUs).
    pub send: Vec<u8>,
    /// ROA record deltas of a completed sync (empty unless `synced`).
    pub roa_deltas: Vec<RoaDelta>,
    /// BGPsec Router Key deltas of a completed sync (empty unless
    /// `synced`). Populated from the §5.10 Router Key PDUs the cache
    /// sent inside the just-closed batch; the client does not run
    /// BGPsec validation itself — the deltas surface the cache's
    /// attestation so an embedder that does (or a future validation
    /// hook) sees the atomic update. Empty for v0 caches (Router Key
    /// is a v1+ PDU; a v0 session never carries one).
    pub router_key_deltas: Vec<RouterKeyDelta>,
    /// ASPA deltas of a completed sync (empty unless `synced`).
    /// Populated from the §5.11 ASPA PDUs the cache sent inside the
    /// just-closed batch; the client does not run ASPA validation
    /// itself — the deltas surface the cache's attestation so an
    /// embedder that does (or a future validation hook) sees the
    /// atomic update. Empty for v0/v1 caches (ASPA is a v2+ PDU).
    pub aspa_deltas: Vec<AspaDelta>,
    /// True when a sync completed (End of Data processed): the
    /// deltas (or [`RtrClient::snapshot`]) are now authoritative.
    pub synced: bool,
    /// True when the transport connection should be closed.
    pub drop: bool,
    /// True when the last synced data exceeded its expire interval
    /// without a successful poll (§6) — validation on it must stop.
    pub expired: bool,
    /// Diagnostic log lines for the embedder's logging surface.
    pub logs: Vec<String>,
}

/// The RTR client state machine for one cache.
#[derive(Debug, Clone)]
pub struct RtrClient {
    /// The protocol version in use (starts at [`RTR_VERSION_MAX`],
    /// downgrades per §7 until the first completed sync).
    version: u8,
    /// The cache session ID (None until the first Cache Response).
    session_id: Option<u16>,
    /// The serial of the last completed sync (None until first EoD).
    serial: Option<u32>,
    phase: Phase,
    /// Authoritative record set of the last completed sync.
    records: HashSet<RoaEntry>,
    /// The batch accumulating since the current Cache Response.
    batch: HashSet<RoaEntry>,
    /// Authoritative BGPsec Router Key set of the last completed
    /// sync (RFC 8210 §5.10). The client does not run BGPsec
    /// validation; the set is the cache's attestation, surfaced
    /// through [`ClientStep::router_key_deltas`] at End of Data.
    router_keys: HashSet<RouterKeyEntry>,
    /// The Router Key batch accumulating since the current Cache
    /// Response. Cleared at Cache Response (AwaitingReset) and
    /// cloned from the authoritative set (AwaitingSerial), matching
    /// the ROA batch's lifecycle.
    router_key_batch: HashSet<RouterKeyEntry>,
    /// Authoritative ASPA record set of the last completed sync
    /// (RFC 8210 §5.11, SIDROPS ASPA profile). The client does not
    /// run ASPA validation; the set is the cache's attestation,
    /// surfaced through [`ClientStep::aspa_deltas`] at End of Data.
    aspa_records: HashSet<AspaEntry>,
    /// The ASPA batch accumulating since the current Cache Response.
    /// Cleared at Cache Response (AwaitingReset) and cloned from
    /// the authoritative set (AwaitingSerial), matching the ROA
    /// batch's lifecycle.
    aspa_batch: HashSet<AspaEntry>,
    /// Cache-provided timing (§6): v1+ End-of-Data values override;
    /// v0 End-of-Data leaves the configured values standing.
    refresh_interval: u32,
    retry_interval: u32,
    expire_interval: u32,
    /// When the last EoD was processed (embedder clock, ms).
    last_sync_ms: Option<u64>,
}

impl Default for RtrClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RtrClient {
    /// A client starting at [`RTR_VERSION_MAX`] with no session
    /// memory — the cold-start state of §8.1.
    pub fn new() -> Self {
        Self {
            version: RTR_VERSION_MAX,
            session_id: None,
            serial: None,
            phase: Phase::AwaitingReset,
            records: HashSet::new(),
            batch: HashSet::new(),
            router_keys: HashSet::new(),
            router_key_batch: HashSet::new(),
            aspa_records: HashSet::new(),
            aspa_batch: HashSet::new(),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            retry_interval: DEFAULT_RETRY_INTERVAL,
            expire_interval: DEFAULT_EXPIRE_INTERVAL,
            last_sync_ms: None,
        }
    }

    /// The protocol version currently spoken (post-§7 downgrade).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The remembered session ID (present once a Cache Response was
    /// received).
    pub fn session_id(&self) -> Option<u16> {
        self.session_id
    }

    /// The serial of the last completed sync.
    pub fn serial(&self) -> Option<u32> {
        self.serial
    }

    /// The authoritative record set after the last completed sync,
    /// sorted for deterministic snapshots.
    pub fn snapshot(&self) -> Vec<RoaEntry> {
        let mut out: Vec<RoaEntry> = self.records.iter().copied().collect();
        out.sort_by_key(|e| (e.prefix, e.max_length, e.asn));
        out
    }

    /// The authoritative BGPsec Router Key set after the last completed
    /// sync (RFC 8210 §5.10), sorted for deterministic snapshots. The
    /// client does not run BGPsec validation — the snapshot is the
    /// cache's attestation, surfaced for an embedder that does.
    pub fn router_key_snapshot(&self) -> Vec<RouterKeyEntry> {
        let mut out: Vec<RouterKeyEntry> = self.router_keys.iter().cloned().collect();
        out.sort_by_key(|e| (e.asn, e.ski));
        out
    }

    /// The authoritative ASPA record set after the last completed sync
    /// (RFC 8210 §5.11, SIDROPS ASPA profile), sorted for deterministic
    /// snapshots. The client does not run ASPA validation — the
    /// snapshot is the cache's attestation, surfaced for an embedder
    /// that does.
    pub fn aspa_snapshot(&self) -> Vec<AspaEntry> {
        let mut out: Vec<AspaEntry> = self.aspa_records.iter().cloned().collect();
        out.sort_by_key(|e| e.customer_asn);
        out
    }

    /// The current phase name (diagnostics: "awaiting-reset",
    /// "awaiting-serial", "receiving", "synced").
    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::AwaitingReset => "awaiting-reset",
            Phase::AwaitingSerial => "awaiting-serial",
            Phase::ReceivingPayload => "receiving",
            Phase::Synced => "synced",
        }
    }

    /// The §6 timing intervals currently in effect (from the last
    /// End of Data, or the defaults).
    pub fn intervals(&self) -> (u32, u32, u32) {
        (
            self.refresh_interval,
            self.retry_interval,
            self.expire_interval,
        )
    }

    /// Override the initial §6 intervals (refresh, retry, expire —
    /// seconds). The embedder calls this once at construction from
    /// its configuration; a v1+ cache replaces all three from every
    /// End-of-Data PDU (§6), so this only shapes the behaviour before
    /// the first End of Data and for v0 caches.
    pub fn set_intervals(&mut self, refresh: u32, retry: u32, expire: u32) {
        self.refresh_interval = refresh;
        self.retry_interval = retry;
        self.expire_interval = expire;
    }

    /// Bytes to transmit when the transport comes up (§8.1): a Serial
    /// Query when the client remembers an unexpired session, a Reset
    /// Query otherwise. Also (re)arms the phase tracking.
    pub fn on_connect(&mut self) -> Vec<u8> {
        let pdu = match (self.session_id, self.serial) {
            (Some(session), Some(serial)) => {
                self.phase = Phase::AwaitingSerial;
                RtrPdu::SerialQuery {
                    session_id: session,
                    serial,
                }
            }
            _ => {
                self.phase = Phase::AwaitingReset;
                RtrPdu::ResetQuery
            }
        };
        let mut out = Vec::new();
        encode(&pdu, self.version, &mut out);
        out
    }

    /// Consume one decoded PDU (with its wire version) and produce
    /// the next protocol step.
    pub fn on_pdu(&mut self, version: u8, pdu: &RtrPdu, now_ms: u64) -> ClientStep {
        let mut step = ClientStep::default();

        // §5.11 / §12 code 8: a PDU at a HIGHER version than the
        // session speaks is a protocol violation — report and drop.
        // (The §7 downgrade below only ever moves the session DOWN;
        // a higher version cannot be honored because the client has
        // already encoded its queries at the session version.)
        if version > self.version && !matches!(pdu, RtrPdu::Aspa { .. }) {
            // The SIDROPS ASPA profile pins the ASPA PDU at version 2
            // (the codec's per-type gate); a v2 ASPA inside a v1
            // session is legal — BIRD's parser accepts exactly that.
            // Any other PDU above the session version is a §5.11
            // violation: report and drop.
            step.logs.push(format!(
                "rtr: unexpected protocol version {version} (session speaks {}) — reporting and dropping",
                self.version
            ));
            self.error_report(
                &mut step,
                RtrErrorCode::UnexpectedProtocolVersion,
                "pdu version is higher than the session version",
            );
            step.drop = true;
            return step;
        }

        // §7: during startup (before the first completed sync) any
        // PDU at a lower *known* version downgrades the session.
        // Serial Notify is ignored outright in this window, whatever
        // its version.
        if self.serial.is_none() {
            if let RtrPdu::SerialNotify { .. } = pdu {
                step.logs.push(format!(
                    "rtr: serial notify during startup ignored (v{version})"
                ));
                return step;
            }
            if version < self.version && version <= RTR_VERSION_MAX {
                step.logs.push(format!(
                    "rtr: downgrading to protocol version {version} (was {})",
                    self.version
                ));
                self.version = version;
            }
        }

        match pdu {
            RtrPdu::SerialNotify { session_id, serial } => {
                // §5.2: an immediate Serial Query is allowed once
                // synced; a different session means the cache
                // restarted — a Reset Query rebuilds from scratch.
                if self.phase == Phase::Synced {
                    if Some(*session_id) == self.session_id {
                        step.logs.push(format!(
                            "rtr: serial notify {serial} (session {session_id:#06x})"
                        ));
                        let query = RtrPdu::SerialQuery {
                            session_id: *session_id,
                            serial: self.serial.unwrap_or(0),
                        };
                        encode(&query, self.version, &mut step.send);
                        self.phase = Phase::AwaitingSerial;
                    } else {
                        step.logs.push(format!(
                            "rtr: session changed {:#06x} -> {session_id:#06x}, resetting",
                            self.session_id.unwrap_or(0)
                        ));
                        encode(&RtrPdu::ResetQuery, self.version, &mut step.send);
                        self.phase = Phase::AwaitingReset;
                    }
                }
            }
            RtrPdu::CacheResponse { session_id } => {
                match self.phase {
                    Phase::AwaitingReset => {
                        // The full database follows: a fresh batch.
                        self.session_id = Some(*session_id);
                        self.batch.clear();
                        self.router_key_batch.clear();
                        self.aspa_batch.clear();
                        self.phase = Phase::ReceivingPayload;
                    }
                    Phase::AwaitingSerial => {
                        if Some(*session_id) != self.session_id {
                            // §6/§8.1: the serial numbers would not be
                            // commensurate — rebuild via Reset Query.
                            step.logs.push(format!(
                                "rtr: session changed {:#06x} -> {session_id:#06x}, resetting",
                                self.session_id.unwrap_or(0)
                            ));
                            self.session_id = Some(*session_id);
                            self.phase = Phase::AwaitingReset;
                            self.batch.clear();
                            self.router_key_batch.clear();
                            self.aspa_batch.clear();
                            encode(&RtrPdu::ResetQuery, self.version, &mut step.send);
                            return step;
                        }
                        // Incremental: the batch starts from the
                        // current records and the deltas apply on top.
                        self.batch = self.records.clone();
                        self.router_key_batch = self.router_keys.clone();
                        self.aspa_batch = self.aspa_records.clone();
                        self.phase = Phase::ReceivingPayload;
                    }
                    Phase::ReceivingPayload | Phase::Synced => {
                        step.logs.push(format!(
                            "rtr: unexpected cache response in state {}, dropping",
                            self.phase_name()
                        ));
                        self.error_report(
                            &mut step,
                            RtrErrorCode::CorruptData,
                            "cache response in wrong state",
                        );
                        step.drop = true;
                    }
                }
            }
            RtrPdu::Ipv4Prefix {
                announce,
                prefix,
                max_length,
                asn,
            }
            | RtrPdu::Ipv6Prefix {
                announce,
                prefix,
                max_length,
                asn,
            } => {
                if self.phase != Phase::ReceivingPayload {
                    step.logs.push(format!(
                        "rtr: prefix PDU outside a sync in state {}, ignored",
                        self.phase_name()
                    ));
                    return step;
                }
                let entry = match RoaEntry::with_max_length(*prefix, *max_length, Asn::new(*asn)) {
                    Ok(e) => e,
                    Err(e) => {
                        // The codec already validated the invariants;
                        // this is belt-and-braces for future callers.
                        step.logs
                            .push(format!("rtr: bad ROA entry {prefix:?}: {e}"));
                        return step;
                    }
                };
                if *announce {
                    if self.records.contains(&entry) && self.batch.contains(&entry) {
                        // §5.6 duplicate announcement — logged, coalesced.
                        step.logs
                            .push(format!("rtr: duplicate announcement {entry:?}"));
                    }
                    self.batch.insert(entry);
                } else {
                    if !self.batch.remove(&entry) {
                        // §12 code 6 in spirit — a withdrawal of a
                        // record we do not hold. The diff makes it a
                        // no-op; BIRD's channel semantics are equally
                        // lenient. Logged for the operator.
                        step.logs
                            .push(format!("rtr: withdrawal of unknown record {entry:?}"));
                    }
                }
            }
            RtrPdu::EndOfData {
                session_id,
                serial,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                // Phase gate (§5.8): End of Data only closes a batch a
                // Cache Response opened. A stray or duplicate EoD —
                // unsolicited, or while still awaiting the response —
                // would otherwise swap the (possibly empty) batch in
                // as authoritative and emit a spurious withdraw-all;
                // §10 treats the exchange as corrupt instead.
                if self.phase != Phase::ReceivingPayload {
                    step.logs.push(format!(
                        "rtr: end-of-data in state {} — corrupt data, dropping",
                        self.phase_name()
                    ));
                    self.error_report(
                        &mut step,
                        RtrErrorCode::CorruptData,
                        "end-of-data outside a payload batch",
                    );
                    step.drop = true;
                    return step;
                }
                if Some(*session_id) != self.session_id {
                    step.logs.push(format!(
                        "rtr: end-of-data session {session_id:#06x} != {:#06x}, dropping",
                        self.session_id.unwrap_or(0)
                    ));
                    self.error_report(
                        &mut step,
                        RtrErrorCode::CorruptData,
                        "end-of-data session mismatch",
                    );
                    step.drop = true;
                    return step;
                }
                // The batch is now authoritative (§5.8): swap and
                // emit the atomic diff.
                let old = core::mem::replace(&mut self.records, core::mem::take(&mut self.batch));
                step.roa_deltas = diff_records(&old, &self.records);
                // §5.10 / §5.11: the same swap-and-diff applies to the
                // BGPsec Router Key and ASPA batches the cache sent
                // inside this sync. The client does not run BGPsec or
                // ASPA validation itself — the deltas surface the
                // cache's attestation so an embedder (or a future
                // validation hook) sees the atomic update alongside
                // the ROA deltas.
                let old_keys = core::mem::replace(
                    &mut self.router_keys,
                    core::mem::take(&mut self.router_key_batch),
                );
                step.router_key_deltas = diff_router_keys(&old_keys, &self.router_keys);
                let old_aspa = core::mem::replace(
                    &mut self.aspa_records,
                    core::mem::take(&mut self.aspa_batch),
                );
                step.aspa_deltas = diff_aspa_records(&old_aspa, &self.aspa_records);
                self.serial = Some(*serial);
                self.phase = Phase::Synced;
                self.last_sync_ms = Some(now_ms);
                // A v1+ cache's values override (§6); a v0 cache carries
                // no intervals, so the embedder's configured ones keep
                // governing (they default to the RFC values when unset).
                self.refresh_interval = refresh_interval.unwrap_or(self.refresh_interval).max(1);
                self.retry_interval = retry_interval.unwrap_or(self.retry_interval).max(1);
                self.expire_interval = expire_interval.unwrap_or(self.expire_interval).max(1);
                step.synced = true;
                step.logs.push(format!(
                    "rtr: synced (session {session_id:#06x}, serial {serial}, {} roas: +{} -{}, {} router keys: +{} -{}, {} aspa: +{} -{})",
                    self.records.len(),
                    step.roa_deltas.iter().filter(|d| d.announce).count(),
                    step.roa_deltas.iter().filter(|d| !d.announce).count(),
                    self.router_keys.len(),
                    step.router_key_deltas.iter().filter(|d| d.announce).count(),
                    step.router_key_deltas.iter().filter(|d| !d.announce).count(),
                    self.aspa_records.len(),
                    step.aspa_deltas.iter().filter(|d| d.announce).count(),
                    step.aspa_deltas.iter().filter(|d| !d.announce).count(),
                ));
            }
            RtrPdu::CacheReset => {
                // §5.9/§8.3: the cache cannot serve the increment —
                // ask for the full database again.
                step.logs.push("rtr: cache reset, re-querying".into());
                self.phase = Phase::AwaitingReset;
                self.batch.clear();
                self.router_key_batch.clear();
                self.aspa_batch.clear();
                encode(&RtrPdu::ResetQuery, self.version, &mut step.send);
            }
            RtrPdu::ErrorReport {
                error_code,
                error_text,
                ..
            } => {
                let text = error_text.as_deref().unwrap_or("");
                step.logs.push(format!(
                    "rtr: error report from cache: {} ({})",
                    error_code.name(),
                    text
                ));
                // §12: everything but No Data Available is fatal; even
                // No Data closes this session (the retry interval
                // governs reconnecting).
                step.drop = true;
            }
            RtrPdu::RouterKey {
                announce,
                ski,
                asn,
                subject_public_key_info,
            } => {
                // §5.10: BGPsec Router Key PDU (v1+). The client does
                // not run BGPsec validation; the entry is accumulated
                // into the per-sync batch so End of Data surfaces it
                // as a typed delta. Outside a sync the PDU is logged
                // and ignored — the same phase gate the ROA path
                // applies to a stray prefix PDU. Previously this arm
                // silently swallowed every Router Key PDU, so an
                // embedder that wanted to consume the cache's
                // attestation (BGPsec path validation, or operator
                // visibility) saw nothing; the deltas now carry the
                // data through.
                //
                // The entry identity is `(ski, asn)` (see
                // [`RouterKeyEntry`]'s `PartialEq`/`Hash`); the SPKI
                // is the attested data. A re-announcement with a
                // different SPKI replaces the prior attestation —
                // `HashSet::insert` would no-op on a duplicate
                // identity, so remove first to make the replacement
                // stick.
                if self.phase != Phase::ReceivingPayload {
                    step.logs.push(format!(
                        "rtr: router key PDU outside a sync in state {}, ignored",
                        self.phase_name()
                    ));
                    return step;
                }
                let entry = RouterKeyEntry {
                    ski: *ski,
                    asn: *asn,
                    subject_public_key_info: subject_public_key_info.clone(),
                };
                if *announce {
                    self.router_key_batch.remove(&entry);
                    self.router_key_batch.insert(entry);
                } else if !self.router_key_batch.remove(&entry) {
                    step.logs
                        .push(format!("rtr: withdrawal of unknown router key (asn {asn})"));
                }
            }
            RtrPdu::Aspa {
                announce,
                customer_asn,
                providers,
            } => {
                // §5.11 (SIDROPS ASPA profile, v2+): the provider set
                // of one customer AS. The client does not run ASPA
                // validation; the entry is accumulated into the
                // per-sync batch so End of Data surfaces it as a typed
                // delta. Outside a sync the PDU is logged and ignored
                // — the same phase gate the ROA path applies. A
                // withdrawal (`announce = false`) deletes the whole
                // customer record (RFC 8210 §5.11), so any entry
                // whose `customer_asn` matches is removed regardless
                // of the providers vec the withdrawal carries.
                //
                // The entry identity is `customer_asn` (see
                // [`AspaEntry`]'s `PartialEq`/`Hash`); the providers
                // set is the attested data. A re-announcement with a
                // different provider set replaces the prior
                // attestation — `HashSet::insert` would no-op on a
                // duplicate identity, so remove first to make the
                // replacement stick.
                if self.phase != Phase::ReceivingPayload {
                    step.logs.push(format!(
                        "rtr: aspa PDU outside a sync in state {}, ignored",
                        self.phase_name()
                    ));
                    return step;
                }
                let entry = AspaEntry {
                    customer_asn: *customer_asn,
                    providers: providers.iter().copied().collect(),
                };
                if *announce {
                    self.aspa_batch.remove(&entry);
                    self.aspa_batch.insert(entry);
                } else {
                    // §5.11: a withdrawal deletes the entire customer
                    // record. `HashSet::remove` with the custom
                    // identity-only `Hash`/`Eq` matches any entry
                    // for `customer_asn`, so a withdrawal with an
                    // empty providers vec still removes the
                    // previously-announced entry.
                    if !self.aspa_batch.remove(&entry) {
                        step.logs.push(format!(
                            "rtr: aspa withdrawal of unknown customer {customer_asn}"
                        ));
                    }
                }
            }
            RtrPdu::SerialQuery { .. } | RtrPdu::ResetQuery => {
                // Router-to-cache PDUs from the cache side are noise.
                step.logs.push(format!(
                    "rtr: unexpected {} from cache, ignored",
                    pdu.pdu_type().name()
                ));
            }
        }
        step
    }

    /// Apply the §6 timing rules. Returns the step for this tick:
    /// while synced past the refresh interval a Serial Query goes
    /// out; once past the expire interval without a sync the data is
    /// reported expired (every call until a sync succeeds).
    pub fn poll(&mut self, now_ms: u64) -> ClientStep {
        let mut step = ClientStep::default();
        let Some(last) = self.last_sync_ms else {
            return step;
        };
        let refresh_ms = u64::from(self.refresh_interval) * 1000;
        let expire_ms = u64::from(self.expire_interval) * 1000;
        if now_ms.saturating_sub(last) >= expire_ms {
            step.expired = true;
            step.logs
                .push("rtr: data expired (no successful sync in window)".into());
            return step;
        }
        if self.phase == Phase::Synced && now_ms.saturating_sub(last) >= refresh_ms {
            let query = RtrPdu::SerialQuery {
                session_id: self.session_id.unwrap_or(0),
                serial: self.serial.unwrap_or(0),
            };
            encode(&query, self.version, &mut step.send);
            self.phase = Phase::AwaitingSerial;
            step.logs
                .push("rtr: refresh timer, sending serial query".into());
        }
        step
    }

    /// Queue an Error Report for the cache (§5.11).
    fn error_report(&self, step: &mut ClientStep, code: RtrErrorCode, text: &str) {
        let pdu = RtrPdu::ErrorReport {
            error_code: code,
            erroneous_pdu: Vec::new(),
            error_text: Some(text.to_string()),
        };
        encode(&pdu, self.version, &mut step.send);
    }
}

/// The atomic diff between the old and new authoritative record sets.
fn diff_records(old: &HashSet<RoaEntry>, new: &HashSet<RoaEntry>) -> Vec<RoaDelta> {
    let mut out = Vec::new();
    for entry in new {
        if !old.contains(entry) {
            out.push(RoaDelta {
                announce: true,
                entry: *entry,
            });
        }
    }
    for entry in old {
        if !new.contains(entry) {
            out.push(RoaDelta {
                announce: false,
                entry: *entry,
            });
        }
    }
    out
}

/// The atomic diff between the old and new authoritative BGPsec Router
/// key sets (RFC 8210 §5.10). The entry identity is `(ski, asn)` —
/// [`RouterKeyEntry`]'s `PartialEq` and `Hash` cover only those two
/// fields. Two entries that share `(ski, asn)` but disagree on the
/// SPKI therefore hash to the same bucket; the diff walks both sets
/// and, for each entry in `new` whose `(ski, asn)` is also in `old`,
/// compares the SPKI verbatim. A SPKI change surfaces as a withdraw of
/// the old entry plus an announce of the new one (matching §5.10: a
/// re-announcement with a different SPKI is by definition a
/// re-attestation, not a no-op).
fn diff_router_keys(
    old: &HashSet<RouterKeyEntry>,
    new: &HashSet<RouterKeyEntry>,
) -> Vec<RouterKeyDelta> {
    let mut out = Vec::new();
    for new_entry in new {
        if let Some(old_entry) = old.get(new_entry) {
            // Same (ski, asn). Compare the SPKI; a change is a
            // re-attestation (withdraw the old, announce the new).
            if new_entry.subject_public_key_info != old_entry.subject_public_key_info {
                out.push(RouterKeyDelta {
                    announce: false,
                    entry: old_entry.clone(),
                });
                out.push(RouterKeyDelta {
                    announce: true,
                    entry: new_entry.clone(),
                });
            }
            // Else: identical (ski, asn, spki) — no delta.
        } else {
            // New (ski, asn) — announce.
            out.push(RouterKeyDelta {
                announce: true,
                entry: new_entry.clone(),
            });
        }
    }
    for old_entry in old {
        if !new.contains(old_entry) {
            // Removed (ski, asn) — withdraw.
            out.push(RouterKeyDelta {
                announce: false,
                entry: old_entry.clone(),
            });
        }
    }
    out
}

/// The atomic diff between the old and new authoritative ASPA record
/// sets (RFC 8210 §5.11, SIDROPS ASPA profile). The entry identity is
/// `customer_asn` — [`AspaEntry`]'s `PartialEq` and `Hash` cover only
/// that field. The diff walks both sets and, for each entry in `new`
/// whose `customer_asn` is also in `old`, compares the provider set
/// verbatim. A provider-set change surfaces as a withdraw of the old
/// entry plus an announce of the new one (matching §5.11's "replace
/// the entire ASPA object" semantics).
fn diff_aspa_records(old: &HashSet<AspaEntry>, new: &HashSet<AspaEntry>) -> Vec<AspaDelta> {
    let mut out = Vec::new();
    for new_entry in new {
        if let Some(old_entry) = old.get(new_entry) {
            // Same customer_asn. Compare the provider sets; a change
            // is a re-attestation (withdraw the old, announce the new).
            if new_entry.providers != old_entry.providers {
                out.push(AspaDelta {
                    announce: false,
                    entry: old_entry.clone(),
                });
                out.push(AspaDelta {
                    announce: true,
                    entry: new_entry.clone(),
                });
            }
            // Else: identical (customer_asn, providers) — no delta.
        } else {
            // New customer — announce.
            out.push(AspaDelta {
                announce: true,
                entry: new_entry.clone(),
            });
        }
    }
    for old_entry in old {
        if !new.contains(old_entry) {
            // Removed customer — withdraw.
            out.push(AspaDelta {
                announce: false,
                entry: old_entry.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
