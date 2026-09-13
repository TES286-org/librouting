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

use std::collections::HashSet;

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

/// What the embedder should do after one protocol step.
#[derive(Debug, Default, Clone)]
pub struct ClientStep {
    /// Wire bytes to transmit (zero or more complete PDUs).
    pub send: Vec<u8>,
    /// ROA record deltas of a completed sync (empty unless `synced`).
    pub roa_deltas: Vec<RoaDelta>,
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
                            encode(&RtrPdu::ResetQuery, self.version, &mut step.send);
                            return step;
                        }
                        // Incremental: the batch starts from the
                        // current records and the deltas apply on top.
                        self.batch = self.records.clone();
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
                    "rtr: synced (session {session_id:#06x}, serial {serial}, {} roas: +{} -{})",
                    self.records.len(),
                    step.roa_deltas.iter().filter(|d| d.announce).count(),
                    step.roa_deltas.iter().filter(|d| !d.announce).count(),
                ));
            }
            RtrPdu::CacheReset => {
                // §5.9/§8.3: the cache cannot serve the increment —
                // ask for the full database again.
                step.logs.push("rtr: cache reset, re-querying".into());
                self.phase = Phase::AwaitingReset;
                self.batch.clear();
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
            RtrPdu::RouterKey { .. } | RtrPdu::Aspa { .. } => {
                // Accepted on the wire (the codec validates them) but
                // not used for origin validation yet — BIRD's parity
                // is to skip Router Key PDUs it cannot use.
                step.logs.push(format!(
                    "rtr: {} PDU accepted but unused",
                    pdu.pdu_type().name()
                ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtr::pdu::{
        decode, encode_vec, RtrPdu, RTR_VERSION_0, RTR_VERSION_1, RTR_VERSION_2,
    };
    use lr_core::addr::{Asn, Prefix};

    const V: u8 = RTR_VERSION_1;
    const NOW: u64 = 1_000;

    fn roa(addr: [u8; 4], plen: u8, max: u8, asn: u32) -> RoaEntry {
        RoaEntry::with_max_length(Prefix::new_v4(addr, plen), max, Asn::new(asn)).unwrap()
    }

    fn feed(client: &mut RtrClient, pdu: &RtrPdu, now_ms: u64) -> ClientStep {
        // ASPA needs v2; encode each PDU at the session version or
        // its own minimum, whichever is higher.
        let wire = encode_vec(pdu, V.max(pdu.min_version()));
        let (ver, decoded, _) = decode(&wire).unwrap().unwrap();
        client.on_pdu(ver, &decoded, now_ms)
    }

    fn cache_response(session: u16) -> RtrPdu {
        RtrPdu::CacheResponse {
            session_id: session,
        }
    }

    fn eod(session: u16, serial: u32) -> RtrPdu {
        RtrPdu::EndOfData {
            session_id: session,
            serial,
            refresh_interval: Some(60),
            retry_interval: Some(30),
            expire_interval: Some(600),
        }
    }

    fn announced(entry: &RoaEntry) -> RtrPdu {
        RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: entry.prefix,
            max_length: entry.max_length,
            asn: entry.asn.as_u32(),
        }
    }

    fn withdrawn(entry: &RoaEntry) -> RtrPdu {
        RtrPdu::Ipv4Prefix {
            announce: false,
            prefix: entry.prefix,
            max_length: entry.max_length,
            asn: entry.asn.as_u32(),
        }
    }

    /// Decode the first PDU in a send buffer.
    fn first_query(send: &[u8]) -> RtrPdu {
        let (_v, out, _n) = decode(send).unwrap().unwrap();
        out
    }

    #[test]
    fn cold_start_sends_reset_query_and_full_sync() {
        let mut c = RtrClient::new();
        let send = c.on_connect();
        assert_eq!(first_query(&send), RtrPdu::ResetQuery);
        assert_eq!(c.phase_name(), "awaiting-reset");

        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        let b = roa([198, 51, 100, 0], 24, 24, 64513);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &announced(&b), NOW);
        let step = feed(&mut c, &eod(0x00ff, 5), NOW);

        assert!(step.synced);
        assert!(!step.drop);
        assert_eq!(c.session_id(), Some(0x00ff));
        assert_eq!(c.serial(), Some(5));
        assert_eq!(c.phase_name(), "synced");
        assert_eq!(step.roa_deltas.len(), 2);
        assert!(step.roa_deltas.iter().all(|d| d.announce));
        let snap = c.snapshot();
        assert!(snap.contains(&a));
        assert!(snap.contains(&b));
        // Sorted: 192.0.2.0 before 198.51.100.0.
        assert_eq!(snap.first(), Some(&a));
    }

    #[test]
    fn serial_sync_applies_incremental_deltas() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        let b = roa([198, 51, 100, 0], 24, 24, 64513);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &announced(&b), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        // Serial query (refresh timer) then an incremental response:
        // add c, withdraw b.
        let c_net = roa([203, 0, 113, 0], 24, 24, 64514);
        let step = c.poll(NOW + 61_000);
        assert_eq!(
            first_query(&step.send),
            RtrPdu::SerialQuery {
                session_id: 0x00ff,
                serial: 5
            }
        );
        feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
        feed(&mut c, &announced(&c_net), NOW + 61_000);
        feed(&mut c, &withdrawn(&b), NOW + 61_000);
        let step = feed(&mut c, &eod(0x00ff, 6), NOW + 61_000);

        assert!(step.synced);
        assert_eq!(c.serial(), Some(6));
        let announced: Vec<_> = step
            .roa_deltas
            .iter()
            .filter(|d| d.announce)
            .map(|d| d.entry)
            .collect();
        let withdrawn: Vec<_> = step
            .roa_deltas
            .iter()
            .filter(|d| !d.announce)
            .map(|d| d.entry)
            .collect();
        assert_eq!(announced, vec![c_net]);
        assert_eq!(withdrawn, vec![b]);
        assert_eq!(c.snapshot().len(), 2);
    }

    #[test]
    fn reconnect_uses_serial_query_with_remembered_session() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        // A fresh transport connection (§8.1): the remembered
        // (session, serial) makes the first query a Serial Query.
        let send = c.on_connect();
        assert_eq!(
            first_query(&send),
            RtrPdu::SerialQuery {
                session_id: 0x00ff,
                serial: 5
            }
        );
    }

    #[test]
    fn session_change_on_serial_response_reissues_reset() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        // Refresh, but the cache restarted: session changed.
        c.poll(NOW + 61_000);
        let step = feed(&mut c, &cache_response(0x0aaa), NOW + 61_000);
        assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
        assert_eq!(c.session_id(), Some(0x0aaa));
        assert_eq!(c.phase_name(), "awaiting-reset");
    }

    #[test]
    fn serial_notify_triggers_immediate_query_when_synced() {
        let mut c = RtrClient::new();
        c.on_connect();
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        let step = feed(
            &mut c,
            &RtrPdu::SerialNotify {
                session_id: 0x00ff,
                serial: 6,
            },
            NOW + 5_000,
        );
        assert_eq!(
            first_query(&step.send),
            RtrPdu::SerialQuery {
                session_id: 0x00ff,
                serial: 5
            }
        );
    }

    #[test]
    fn serial_notify_from_foreign_session_resets() {
        let mut c = RtrClient::new();
        c.on_connect();
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        let step = feed(
            &mut c,
            &RtrPdu::SerialNotify {
                session_id: 0x0bbb,
                serial: 1,
            },
            NOW + 5_000,
        );
        assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
    }

    #[test]
    fn serial_notify_during_startup_is_ignored() {
        let mut c = RtrClient::new();
        c.on_connect();
        // §7: ignore regardless of version before the first sync.
        let step = feed(
            &mut c,
            &RtrPdu::SerialNotify {
                session_id: 1,
                serial: 9,
            },
            NOW,
        );
        assert!(step.send.is_empty());
        assert!(!step.drop);
        assert_eq!(c.phase_name(), "awaiting-reset");
    }

    #[test]
    fn cache_reset_reissues_reset_query() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);
        c.poll(NOW + 61_000);

        // §8.3: the cache cannot serve the increment.
        let step = feed(&mut c, &RtrPdu::CacheReset, NOW + 61_000);
        assert_eq!(first_query(&step.send), RtrPdu::ResetQuery);
        // Records survive until the reset response replaces them.
        assert_eq!(c.snapshot().len(), 1);
    }

    #[test]
    fn no_data_available_drops_the_session() {
        let mut c = RtrClient::new();
        c.on_connect();
        let step = feed(
            &mut c,
            &RtrPdu::ErrorReport {
                error_code: RtrErrorCode::NoDataAvailable,
                erroneous_pdu: Vec::new(),
                error_text: Some("cache warming up".into()),
            },
            NOW,
        );
        assert!(step.drop);
        // Not an expiry — the cache said "no data", the retry
        // interval governs reconnecting.
        assert!(!step.expired);
    }

    #[test]
    fn fatal_error_report_drops_the_session() {
        let mut c = RtrClient::new();
        c.on_connect();
        let step = feed(
            &mut c,
            &RtrPdu::ErrorReport {
                error_code: RtrErrorCode::UnsupportedPduType,
                erroneous_pdu: Vec::new(),
                error_text: None,
            },
            NOW,
        );
        assert!(step.drop);
        assert!(!step.logs.is_empty());
    }

    #[test]
    fn version_downgrades_before_first_sync() {
        let mut c = RtrClient::new();
        assert_eq!(c.version(), RTR_VERSION_2);
        // The cache answers our v2 query with v1 PDUs.
        feed(&mut c, &cache_response(1), NOW);
        assert_eq!(c.version(), RTR_VERSION_1);
        // After the first completed sync the version is frozen.
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(1, 1), NOW);
        assert_eq!(c.version(), RTR_VERSION_1);
    }

    #[test]
    fn prefix_pdu_outside_a_sync_is_ignored() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        let step = feed(&mut c, &announced(&a), NOW);
        assert!(!step.drop);
        assert!(!step.synced);
        assert!(c.snapshot().is_empty());
    }

    #[test]
    fn end_of_data_session_mismatch_drops() {
        let mut c = RtrClient::new();
        c.on_connect();
        feed(&mut c, &cache_response(0x00ff), NOW);
        let step = feed(&mut c, &eod(0x0aaa, 5), NOW);
        assert!(step.drop);
        assert!(!step.synced);
    }

    #[test]
    fn unknown_withdrawal_is_logged_noop() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        // Serial sync that withdraws something we never had.
        c.poll(NOW + 61_000);
        let ghost = roa([10, 0, 0, 0], 8, 8, 1);
        feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
        let step = feed(&mut c, &withdrawn(&ghost), NOW + 61_000);
        assert!(!step.drop);
        let step = feed(&mut c, &eod(0x00ff, 6), NOW + 61_000);
        assert!(step.synced);
        assert!(step.roa_deltas.is_empty());
        assert_eq!(c.snapshot().len(), 1);
    }

    #[test]
    fn duplicate_announcement_coalesces() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &announced(&a), NOW); // duplicate
        let step = feed(&mut c, &eod(0x00ff, 5), NOW);
        assert_eq!(step.roa_deltas.len(), 1);
        assert_eq!(c.snapshot().len(), 1);
    }

    #[test]
    fn v0_end_of_data_uses_default_intervals() {
        let mut c = RtrClient::new();
        c.on_connect();
        feed(&mut c, &cache_response(1), NOW);
        let step = feed(
            &mut c,
            &RtrPdu::EndOfData {
                session_id: 1,
                serial: 3,
                refresh_interval: None,
                retry_interval: None,
                expire_interval: None,
            },
            NOW,
        );
        assert!(step.synced);
        assert_eq!(
            c.intervals(),
            (
                DEFAULT_REFRESH_INTERVAL,
                DEFAULT_RETRY_INTERVAL,
                DEFAULT_EXPIRE_INTERVAL
            )
        );
    }

    #[test]
    fn refresh_and_expire_timers() {
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        // 60 s refresh, 600 s expire (from the eod below).
        feed(&mut c, &eod(0x00ff, 5), NOW);

        // Before refresh: nothing.
        let step = c.poll(NOW + 59_000);
        assert!(step.send.is_empty());
        // At refresh: serial query.
        let step = c.poll(NOW + 60_000);
        assert_eq!(
            first_query(&step.send),
            RtrPdu::SerialQuery {
                session_id: 0x00ff,
                serial: 5
            }
        );
        // Well past expire (no sync since): expired, no query spam.
        let step = c.poll(NOW + 700_000);
        assert!(step.expired);
        assert!(step.send.is_empty());
    }

    #[test]
    fn router_key_and_aspa_are_accepted_but_unused() {
        let mut c = RtrClient::new();
        c.on_connect();
        feed(&mut c, &cache_response(1), NOW);
        let step = feed(
            &mut c,
            &RtrPdu::RouterKey {
                announce: true,
                ski: [0u8; 20],
                asn: 64512,
                subject_public_key_info: vec![0x30],
            },
            NOW,
        );
        assert!(!step.drop);
        let step = feed(
            &mut c,
            &RtrPdu::Aspa {
                announce: true,
                customer_asn: 64496,
                providers: vec![64500],
            },
            NOW,
        );
        assert!(!step.drop);
        let step = feed(&mut c, &eod(1, 1), NOW);
        assert!(step.synced);
        assert!(step.roa_deltas.is_empty());
    }

    #[test]
    fn same_serial_response_produces_no_deltas() {
        // A serial query answered with the same serial (nothing new):
        // the authoritative set is unchanged.
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 5), NOW);

        c.poll(NOW + 61_000);
        feed(&mut c, &cache_response(0x00ff), NOW + 61_000);
        let step = feed(&mut c, &eod(0x00ff, 5), NOW + 61_000);
        assert!(step.synced);
        assert!(step.roa_deltas.is_empty());
    }

    #[test]
    fn configured_intervals_shape_the_first_refresh() {
        // The embedder's configured intervals apply before the first
        // End of Data: a short refresh polls sooner than the default.
        let mut c = RtrClient::new();
        c.set_intervals(60, 30, 120);
        assert_eq!(c.intervals(), (60, 30, 120));
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 1), NOW);
        // Default refresh is 3600 s — at 61 s an unconfigured client
        // would stay quiet; this one sends its refresh Serial Query.
        let step = c.poll(NOW + 61_000);
        assert!(!step.send.is_empty());
    }

    #[test]
    fn stray_end_of_data_is_corrupt_data_and_records_survive() {
        // A duplicate EoD after a completed sync must NOT swap the
        // (empty) batch in as authoritative — §10: corrupt data,
        // Error Report + drop, records unchanged.
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 1), NOW);
        assert_eq!(c.snapshot().len(), 1);

        let step = feed(&mut c, &eod(0x00ff, 1), NOW);
        assert!(step.drop);
        assert!(!step.synced);
        assert!(step.roa_deltas.is_empty());
        assert_eq!(c.snapshot().len(), 1, "records must survive a stray EoD");
        // The wire carried an Error Report (Corrupt Data).
        let (ver, pdu, _) = decode(&step.send).unwrap().unwrap();
        assert_eq!(ver, RTR_VERSION_1);
        assert!(matches!(
            pdu,
            RtrPdu::ErrorReport {
                error_code: RtrErrorCode::CorruptData,
                ..
            }
        ));

        // Same violation while a query is in flight.
        let mut c = RtrClient::new();
        c.on_connect();
        let step = feed(&mut c, &eod(0x00ff, 1), NOW);
        assert!(step.drop);
        assert!(step.roa_deltas.is_empty());
    }

    #[test]
    fn configured_intervals_survive_v0_end_of_data() {
        // A v0 cache carries no intervals in EoD — the embedder's
        // configured values keep governing (§6: "its configured
        // defaults").
        let mut c = RtrClient::new();
        c.set_intervals(120, 45, 240);
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        // A true v0 EoD (the feed helper speaks v1, whose encoder
        // materializes defaults for the interval fields): encode at
        // version 0 and decode back.
        let wire = encode_vec(
            &RtrPdu::EndOfData {
                session_id: 0x00ff,
                serial: 1,
                refresh_interval: None,
                retry_interval: None,
                expire_interval: None,
            },
            RTR_VERSION_0,
        );
        let (ver, pdu, _) = decode(&wire).unwrap().unwrap();
        assert_eq!(ver, RTR_VERSION_0);
        assert!(matches!(
            &pdu,
            RtrPdu::EndOfData {
                refresh_interval: None,
                ..
            }
        ));
        let step = c.on_pdu(ver, &pdu, NOW);
        assert!(step.synced);
        assert_eq!(c.intervals(), (120, 45, 240));
    }

    #[test]
    fn higher_version_pdu_is_reported_and_dropped() {
        // §5.11 / §12 code 8: the session never speaks a higher
        // version than it sent — a v2 PDU against a v1 session is a
        // violation, not a §7 upgrade.
        let mut c = RtrClient::new();
        c.on_connect();
        let a = roa([192, 0, 2, 0], 24, 24, 64512);
        feed(&mut c, &cache_response(0x00ff), NOW);
        feed(&mut c, &announced(&a), NOW);
        feed(&mut c, &eod(0x00ff, 1), NOW);
        assert_eq!(c.version(), RTR_VERSION_1);

        // A v2 Serial Notify after the sync: fatal, records intact.
        let wire = encode_vec(
            &RtrPdu::SerialNotify {
                session_id: 0x00ff,
                serial: 2,
            },
            RTR_VERSION_2,
        );
        let (ver, pdu, _) = decode(&wire).unwrap().unwrap();
        assert_eq!(ver, RTR_VERSION_2);
        let step = c.on_pdu(ver, &pdu, NOW);
        assert!(step.drop);
        assert!(matches!(
            decode(&step.send).unwrap().unwrap().1,
            RtrPdu::ErrorReport {
                error_code: RtrErrorCode::UnexpectedProtocolVersion,
                ..
            }
        ));
        assert_eq!(c.snapshot().len(), 1);
    }
}
