# BGP's inherent defects — a catalogue with references

This document catalogues defects that are inherent to BGP as specified
in [RFC 4271] — properties that hold for every conforming
implementation, not bugs in any particular one. For each defect it
lists the mechanism, the primary evidence (RFC text, the measurement
and theory literature), the standard mitigations, and what librouting
already implements or deliberately omits. It exists because W6 of the
roadmap (`STATUS.md`) asks the design of any successor mechanism (see
[EXCHANGE-PLANE.md]) to be grounded in what exactly BGP cannot fix
about itself.

Scope: protocol-inherent weaknesses. Out of scope: implementation
faults (parse bugs, FSM deadlocks), policy choices that are
configurable, and operational accidents that any correct speaker can
cause. Sources are the RFCs themselves and the primary literature, not
secondary folklore; every RFC section cited below was checked against
the published text at rfc-editor.org.

## 1. Slow convergence and path exploration

**Mechanism.** BGP is a path-vector protocol: a speaker's decision
process sees only its neighbours' current best paths and must discover
alternatives by querying those neighbours, hop by hop. When a route
fails, the speaker explores its Adj-RIB-In alternates one at a time;
each exploration produces a fresh UPDATE round that must propagate
through the network before the next candidate can be evaluated. The
message volume is proportional to alternate paths per prefix per
failure, and every advertisement is additionally paced by MRAI (§6),
so a single failure can keep a prefix in flux for minutes.

**Evidence.**
* RFC 4271 §9.1 specifies the decision process whose input is only
  the Adj-RIBs-In; there is no mechanism by which a speaker could
  learn a non-neighbour's alternate path, so network-wide exploration
  is inherent to the information model.
* [Labovitz2000] measured post-failure Internet convergence and found
  the dominant component to be path exploration under per-peer timers,
  with convergence regularly exceeding 15 minutes after a single
  session reset — several orders of magnitude above what the data
  plane could afford.
* [Griffin1999] shows the problem is not merely latency: BGP's
  selection rules can fail to converge at all on some policy
  configurations ("BAD GADGET"), formalized as the stable paths
  problem in [Griffin2002]. [GaoRexford2001] gives the classic
  sufficient condition (customer-first preference ordering) under
  which convergence is guaranteed.

**Mitigations.** A failure-detection plane outside BGP (BFD,
[RFC 5880]) so the hold timer (90 s default, RFC 4271 §10) is not the
first thing to notice; graceful restart ([RFC 4724]) and long-lived
stale routes ([RFC 9494]) to decouple control-plane restarts from
data-plane loss; Add-Path ([RFC 7911]) so a route reflector exposes
alternates instead of a single best path, letting downstream speakers
explore locally instead of across the AS graph.

**In lr.** BFD, GR (RFC 4724), LLGR (RFC 9494) and Add-Path (RFC 7911)
are implemented (see `STATUS.md`); the decision process is
deterministic ([RFC 5004]), which addresses the arrival-order
anomalies [Labovitz2000] identified as the second half of the problem.

## 2. Withdrawal propagation storms

**Mechanism.** A session reset (or a reload without GR) removes every
prefix learned over that session at once. Each downstream speaker must
then decide, per prefix, whether an alternate exists; where none does,
the withdrawal propagates further. The combined effect is a burst of
withdrawals followed by a wave of re-announcements as alternate paths
are explored — a volume proportional to prefixes x alternates x
sessions. Because the withdrawal half is not effectively paced in
deployed practice (RFC 4271 §9.2.1.1 requires only a lower bound with
a bounded upper interval and lets implementations pick the technique;
the observed behaviour [Labovitz2000] is prompt withdrawals with
rate-limited re-announcements), the flip-flop between "gone" and
"alternate" repeats for minutes per prefix.

**Evidence.**
* RFC 4271 §9.2 (Update-Send process): "All newly installed routes and
  all newly unfeasible routes for which there is no replacement route
  SHALL be advertised to its peers" — the propagation is mandatory;
  only the pacing is latitude.
* [Labovitz2000] documents the withdrawal-dominated update bursts and
  their inter-provider amplification after a single failure.
* [Labovitz1997] measures the background instability: a large share of
  daily BGP updates are not reachability changes at all but
  policy- and timer-driven duplicates, which raises the baseline the
  storm rides on.

**Mitigations.** Graceful restart ([RFC 4724]) retains the forwarding
state and marks routes stale instead of withdrawing them; LLGR
([RFC 9494]) extends the retention with per-family timers; route
refresh ([RFC 2918]) reconciles the post-reset re-advertisement
without a session reset.

**In lr.** GR and LLGR are implemented end to end (both helper roles,
BIRD-interop-verified) and route refresh is implemented; the daemon
mirrors the fast-fail path with BFD so most resets are detected before
the hold timer expires.

## 3. Route leaks — policy opacity

**Mechanism.** The intended scope of an announcement (customer cone,
peer, transit) exists only in each operator's local filters. Nothing
on the wire states the business relationship, so a misconfigured or
absent filter propagates silently: receivers see a valid-looking path
with no signal that it crosses a valley it should not.

**Evidence.**
* [RFC 7908] defines the problem — "A route leak is the propagation of
  routing announcement(s) beyond their intended scope" — and
  classifies the documented incidents into six types (hairpin
  full-prefix leaks, lateral ISP-ISP-ISP leaks, transit prefixes to
  peers, peer prefixes to transits, re-origination with a data path,
  accidental internal/more-specific leaks).
* [RFC 9234] §1 states the structural gap: existing leak prevention
  relies "on marking routes by operator configuration, with no check
  that the configuration corresponds to that of the External BGP
  (eBGP) neighbor".
* [CaesarRexford2005] documents how real ISPs encode the
  relationships as local route maps — precisely the opacity the leaks
  exploit.

**Mitigations.** Roles and the Only-to-the-Customer attribute
([RFC 9234]) put the relationship on the wire and enforce it
mechanically; [RFC 8212] removes the default import/export so an
unconfigured session propagates nothing; [RFC 7454] codifies the
filter hygiene; IRR- and RPKI-derived filters constrain what may be
announced at all.

**In lr.** RFC 9234 roles/OTC and the RFC 8212 default-deny mode are
implemented (the daemon enables RFC 8212 semantics by default);
filter construction from IRR data is out of scope.

## 4. Origin and path forgery

**Mechanism.** RFC 4271 authenticates the transport (optionally, via
[RFC 2385]/[RFC 5925]) but not the content. Any eBGP speaker may
originate any prefix and may prepend any ASes to any path; the only
content check the protocol mandates is the local-AS loop check
(RFC 4271 §9.3: a route whose AS_PATH contains the local AS "cannot be
viewed as better than any other route"). A forged update therefore
survives every conforming speaker on the path until a human notices.

**Evidence.**
* [RFC 6811] §1 names the gap: one "needs to validate that the AS
  number claiming to originate an address prefix ... is in fact
  authorized by the prefix holder to do so" — and supplies only a
  partial mechanism (ROA-based origin validation).
* [RFC 8205] extends protection to the path itself with per-AS
  signatures; [RFC 7132] is the threat model that scopes what path
  security can and cannot cover.
* [Zhao2001] analyses MOAS conflicts — legitimate multi-origin noise
  that complicates origin-based detection; [Ballani2007] studies
  hijacking and interception against real AS topologies.

**Mitigations.** RPKI ([RFC 6480]) with ROA origin validation
([RFC 6811]); BGPsec ([RFC 8205]) for paths; transport authentication
([RFC 2385]/[RFC 5925]) against on-path tampering; GTSM ([RFC 5082])
against off-path injection a few hops away.

**In lr.** MD5 (RFC 2385), TCP-AO (RFC 5925, kernel-gated) and GTSM
(RFC 5082) are implemented. RPKI/BGPsec are not implemented and are
marked out of scope in `STATUS.md`; the honest consequence is that lr
— like every deployed speaker without them — cannot distinguish a
forged origin or path from a real one.

## 5. iBGP full-mesh scaling and route-reflection limits

**Mechanism.** RFC 4271 requires every iBGP speaker to be peered with
every other speaker in the AS, which is quadratic in the AS size;
RFC 4456 §1 states plainly that "This 'full mesh' requirement clearly
does not scale". Route reflection removes the mesh but introduces two
new defects of its own: (a) a reflector advertises only its best path,
hiding alternates a downstream speaker could have used after a failure
— and, combined with MED (§7), enabling persistent route oscillation;
(b) the reflection topology (cluster list, IGP-metric rules) becomes a
correctness constraint that is easy to misdesign.

**Evidence.**
* [RFC 4456] §1 (the full-mesh problem) and the reflection rules.
* [RFC 3345] §2.1 exhibits a concrete four-router route-reflector
  topology that oscillates forever under MED comparison.
* [RFC 7911] §1 motivates Add-Path directly with the "only one best
  path is advertised" information loss.

**Mitigations.** Route reflection ([RFC 4456]) and confederations
([RFC 5065]) to remove the mesh; Add-Path ([RFC 7911]) to restore
alternates; [RFC 6774] (diverse-path distribution) as a further
proposal for the route-hiding half.

**In lr.** Route reflection (RFC 4456), confederations (RFC 5065) and
Add-Path (RFC 7911) are implemented.

## 6. The MRAI vs. churn trade-off

**Mechanism.** MRAI ([RFC 4271] §9.2.1.1) paces per-destination
advertisements — suggested 30 s on eBGP, 5 s on iBGP (§10). The
interval trades exploration latency against update volume: raising it
damps churn (and the CPU cost of decision-process runs), lowering it
converges faster but amplifies storms (§1, §2 above). There is no
principled value; every network sits somewhere on the curve, and the
asymmetry with un-paced withdrawals means the pacing shapes only the
repair wave, never the failure wave.

**Evidence.**
* [RFC 4271] §9.2.1.1 — the latitude: "Any technique that ensures that
  the interval between two UPDATE messages ... will be at least
  MinRouteAdvertisementIntervalTimer, and will also ensure that a
  constant upper bound on the interval is acceptable".
* [Labovitz2000] is the canonical measurement of the latency side of
  the trade-off.

**Route flap damping.** The companion mechanism [RFC 2439] attacks the
churn side by penalizing unstable prefixes, but the default parameters
punish exactly the well-connected networks: [Mao2002] showed RFD
*exacerbates* convergence (each explored alternate path of §1
re-triggers the penalty), and the operators' consensus turned it off
([RIPE378]). [RFC 7196] records the deployment status and prescribes
the parameter changes that make damping usable again.

**In lr.** MRAI is implemented (§9.2.1.1 pacing with the iBGP/eBGP
split). Route flap damping lives in the opt-in `lr-damping` crate
(RFC 2439 algorithm, Cisco-style defaults, configurable toward the
RFC 7196 conservative settings) and is off by default for the
[Mao2002] reason.

## 7. MED-induced oscillation

**Mechanism.** MED is "only comparable between routes learned from the
same neighboring AS" (RFC 4271 §9.1.2.2 c). The decision process is
therefore not a total order across speakers: the outcome of comparing
two routes can depend on which other routes are present, i.e. on
arrival order and reflector topology. Under route reflection or
confederations this non-determinism closes a feedback loop and the
network can oscillate forever with no route change external to it.

**Evidence.**
* [RFC 3345] defines Type I churn (persistent MED-induced oscillation
  with route reflection, §2.1, and confederations, §2.2) and Type II
  churn (§3, sustained oscillation without MED, driven by BGP's
  re-advertisement rules).
* [Griffin1999] generalizes: with non-monotone policies the protocol
  has no convergence guarantee ([Griffin2002] formalizes it).
* [RFC 5004] §1 proposes the deterministic comparison order "to
  eliminate certain BGP route oscillations in which more than one
  external path from one BGP speaker contributes to the churn".

**Mitigations.** Deterministic best-path selection ([RFC 5004]);
`always-compare-med` and `missing-MED-as-worst` operational knobs
(removing the same-AS restriction the RFC baked in); keeping MED out
of inter-AS comparisons by policy.

**In lr.** The decision process implements all three:
`deterministic_router_id` (default on, RFC 5004), `always_compare_med`
and `missing_med_as_infinity` (both off by default, mirroring the RFC
latitude) in `lr-bgp::best_path`.

## Summary

| # | Defect | Standard mitigation | lr status |
|---|--------|---------------------|-----------|
| 1 | Path-explorer convergence latency | BFD, GR, LLGR, Add-Path | implemented |
| 2 | Withdrawal storms on session reset | GR, LLGR, route refresh | implemented |
| 3 | Route leaks (policy opacity) | RFC 9234 OTC, RFC 8212, RFC 7454 | OTC + RFC 8212 implemented |
| 4 | Origin/path forgery | RPKI ROA, BGPsec, TCP-AO/MD5, GTSM | transport auth + GTSM; no RPKI/BGPsec (out of scope) |
| 5 | Full-mesh scaling; RR route hiding | RR, confederations, Add-Path | implemented |
| 6 | MRAI/churn trade-off; damping harm | RFC 4271 §9.2.1.1 latitude, RFC 7196 params | MRAI implemented; damping opt-in |
| 7 | MED oscillation | RFC 5004 deterministic order, MED knobs | implemented (default deterministic) |

The pattern across the table: every mitigated defect was patched with
a bolt-on that preserves the base protocol's shape. The defects that
remain unpatched in practice — origin/path forgery (no deployed
crypto), the exploration-latency floor, and the opacity of policy
intent — are the design space W6.2 ([EXCHANGE-PLANE.md]) targets.

## References

RFCs (author lists, titles and dates verified against the published
headers; quoted sections verified against the text):

* [RFC 2385] Heffernan, A., "Protection of BGP Sessions via the TCP
  MD5 Signature Option", RFC 2385, August 1998.
* [RFC 2439] Villamizar, C., Chandra, R., Govindan, R., "BGP Route
  Flap Damping", RFC 2439, November 1998.
* [RFC 2918] Chen, E., "Route Refresh Capability for BGP-4", RFC 2918,
  September 2000.
* [RFC 4271] Rekhter, Y., Li, T., Hares, S., Eds., "A Border Gateway
  Protocol 4 (BGP-4)", RFC 4271, January 2006. Cited: §9.1, §9.1.2.2,
  §9.2, §9.2.1.1, §9.3, §10.
* [RFC 4456] Bates, T., Chen, E., Chandra, R., "BGP Route Reflection:
  An Alternative to Full Mesh Internal BGP (IBGP)", RFC 4456,
  April 2006. Cited: §1.
* [RFC 4724] Sangli, S., Chen, E., Fernando, R., Scudder, J.,
  Rekhter, Y., "Graceful Restart Mechanism for BGP", RFC 4724,
  January 2007.
* [RFC 5004] Chen, E., Fernando, R., "Avoid BGP Best Path Transitions
  from One External to Another", RFC 5004, September 2007. Cited: §1.
* [RFC 5065] Traina, P., McPherson, D., Scudder, J., "Autonomous
  System Confederations for BGP", RFC 5065, August 2007.
* [RFC 5082] Gill, V., Heasley, J., Meyer, D., Savola, P., Ed.,
  Pignataro, C., "The Generalized TTL Security Mechanism (GTSM)",
  RFC 5082, October 2007.
* [RFC 5880] Katz, D., Ward, D., "Bidirectional Forwarding Detection
  (BFD)", RFC 5880, June 2010.
* [RFC 5925] Touch, J., Mankin, A., Bonica, R., "The TCP
  Authentication Option", RFC 5925, June 2010.
* [RFC 6480] Lepinski, M., Kent, S., "An Infrastructure to Support
  Secure Internet Routing", RFC 6480, February 2012.
* [RFC 6774] Raszuk, R., Ed., Fernando, R., Patel, K., McPherson, D.,
  Kumaki, K., "Distribution of Diverse BGP Paths", RFC 6774,
  November 2012.
* [RFC 6811] Mohapatra, P., Scudder, J., Ward, D., Bush, R.,
  Austein, R., "BGP Prefix Origin Validation", RFC 6811, January
  2013. Cited: §1.
* [RFC 7132] Kent, S., Chi, A., "Threat Model for BGP Path Security",
  RFC 7132, February 2014.
* [RFC 7196] Pelsser, C., Bush, R., Patel, K., Mohapatra, P.,
  Maennel, O., "Making Route Flap Damping Usable", RFC 7196, May
  2014. Cited: Abstract, §1.
* [RFC 7454] Durand, J., Pepelnjak, I., Doering, G., "BGP Operations
  and Security", BCP 194, RFC 7454, February 2015.
* [RFC 7908] Sriram, K., Montgomery, D., McPherson, D., Robachevsky,
  O., Randhawa, S., "Problem Definition and Classification of BGP
  Route Leaks", RFC 7908, June 2016. Cited: §1-§3.
* [RFC 7911] Walton, D., Retana, A., Chen, E., Scudder, J.,
  "Advertisement of Multiple Paths in BGP", RFC 7911, July 2016.
  Cited: §1.
* [RFC 8205] Lepinski, M., Ed., Sriram, K., Ed., "BGPsec Protocol
  Specification", RFC 8205, September 2017.
* [RFC 8212] Mauch, J., Snijders, J., Hankins, G., "Default External
  BGP (EBGP) Route Propagation Behavior without Policies", RFC 8212,
  July 2017.
* [RFC 9234] Azimov, A., Bogomazov, E., Bush, R., Patel, K.,
  Sriram, K., "Route Leak Prevention and Detection Using Roles in
  UPDATE and OPEN Messages", RFC 9234, May 2022. Cited: §1.
* [RFC 9494] Uttaro, J., Chen, E., Decraene, B., Scudder, J.,
  "Long-Lived Graceful Restart (LLGR) for BGP", RFC 9494, November
  2023.

Papers:

* [Labovitz1997] Labovitz, C., Malan, G. R., Jahanian, F., "Internet
  Routing Instability", ACM SIGCOMM 1997; reprinted in IEEE/ACM
  Transactions on Networking 6(5), 1998.
* [Labovitz2000] Labovitz, C., Ahuja, A., Bose, A., Jahanian, F.,
  "Delayed Internet Routing Convergence", ACM SIGCOMM 2000.
* [Griffin1999] Griffin, T. G., Wilfong, G., "An Analysis of BGP
  Convergence Properties", ACM SIGCOMM 1999.
* [Griffin2002] Griffin, T. G., Shepherd, F. B., Wilfong, G., "The
  Stable Paths Problem and Interdomain Routing", IEEE/ACM Transactions
  on Networking 10(3), 2002.
* [GaoRexford2001] Gao, L., Rexford, J., "Stable Internet Routing
  without Global Coordination", IEEE/ACM Transactions on Networking
  9(6), 2001.
* [Mao2002] Mao, Z. M., Govindan, R., Varghese, G., Katz, R., "Route
  Flap Damping Exacerbates Internet Routing Convergence", ACM SIGCOMM
  2002.
* [RIPE378] Smith, P., Panigl, C., "RIPE Routing Working Group
  Recommendations On Route-flap Damping", RIPE-378.
* [CaesarRexford2005] Caesar, M., Rexford, J., "BGP Routing Policies
  in ISP Networks", IEEE Network 19(6), 2005.
* [Zhao2001] Zhao, X., Pei, D., Wang, L., Zhang, D., Wang, Y., "An
  Analysis of BGP Multiple Origin AS (MOAS) Conflicts", ACM SIGCOMM
  Internet Measurement Workshop 2001.
* [Ballani2007] Ballani, H., Francis, P., Zhang, X., "A Study of
  Prefix Hijacking and Interception in the Internet", ACM SIGCOMM
  2007.
