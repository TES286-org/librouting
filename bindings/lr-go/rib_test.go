// RIB (LocRib / AdjRibIn / AdjRibOut / RibMux / RouteSelector) tests.
//
// These tests exercise the Go binding through the public API and
// mirror the C ABI tests in crates/lr-ffi/src/rib.rs and the Python
// tests in bindings/lr-python/tests/test_rib.py.

package librouting

import (
	"testing"
)

func v4Route(t *testing.T, addr [4]byte, prefixLen uint8, proto Protocol) *Route {
	t.Helper()
	r, err := NewRouteV4(addr, prefixLen, proto)
	if err != nil {
		t.Fatalf("NewRouteV4(%v, %d, %d): %v", addr, prefixLen, proto, err)
	}
	return r
}

func v4Key(addr [4]byte, prefixLen uint8) RouteKey {
	return RouteKey{
		Addr:      addr[:],
		PrefixLen: prefixLen,
		AFI:       AFIIPv4,
		SAFI:      SAFIUnicast,
	}
}

// ---- LocRib ----

func TestLocRibLifecycle(t *testing.T) {
	r, err := NewLocRib()
	if err != nil {
		t.Fatalf("NewLocRib: %v", err)
	}
	defer r.Free()

	if !r.IsEmpty() {
		t.Fatalf("fresh LocRib not empty")
	}
	if r.Len() != 0 {
		t.Fatalf("Len: got %d want 0", r.Len())
	}
	if r.PathsLen() != 0 {
		t.Fatalf("PathsLen: got %d want 0", r.PathsLen())
	}
	if r.Generation() != 0 {
		t.Fatalf("Generation: got %d want 0", r.Generation())
	}
}

func TestLocRibInstallAndUninstall(t *testing.T) {
	r, err := NewLocRib()
	if err != nil {
		t.Fatalf("NewLocRib: %v", err)
	}
	defer r.Free()

	rt := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	rt.SetNextHop([]byte{10, 0, 0, 254})
	changed, err := r.Install(rt)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !changed {
		t.Fatalf("Install: expected changed=true")
	}
	if r.Len() != 1 {
		t.Fatalf("Len after Install: got %d want 1", r.Len())
	}
	if r.PathsLen() != 1 {
		t.Fatalf("PathsLen after Install: got %d want 1", r.PathsLen())
	}
	gen0 := r.Generation()
	if gen0 < 1 {
		t.Fatalf("Generation after Install: got %d want >= 1", gen0)
	}

	// Installing the same route again is a byte-identical no-op.
	rt2 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	rt2.SetNextHop([]byte{10, 0, 0, 254})
	changed2, err := r.Install(rt2)
	if err != nil {
		t.Fatalf("Install (no-op): %v", err)
	}
	if changed2 {
		t.Fatalf("Install (no-op): expected changed=false")
	}
	if r.Generation() != gen0 {
		t.Fatalf("Generation bumped on no-op install: %d vs %d", r.Generation(), gen0)
	}

	// Best.
	k := v4Key([4]byte{10, 0, 0, 1}, 24)
	if !r.BestPresent(k) {
		t.Fatalf("BestPresent: false")
	}
	best, err := r.Best(k)
	if err != nil {
		t.Fatalf("Best: %v", err)
	}
	if best == nil {
		t.Fatalf("Best: nil")
	}
	defer best.Free()

	// Uninstall.
	if ok, err := r.Uninstall(k); err != nil || !ok {
		t.Fatalf("Uninstall: ok=%v err=%v", ok, err)
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Uninstall: got %d want 0", r.Len())
	}
	if r.BestPresent(k) {
		t.Fatalf("BestPresent after Uninstall: still true")
	}
	// Second Uninstall is a no-op.
	if ok, err := r.Uninstall(k); err != nil || ok {
		t.Fatalf("Uninstall (no-op): ok=%v err=%v", ok, err)
	}
}

func TestLocRibInstallSetAndIter(t *testing.T) {
	r, err := NewLocRib()
	if err != nil {
		t.Fatalf("NewLocRib: %v", err)
	}
	defer r.Free()

	r1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r1.SetNextHop([]byte{10, 0, 0, 254})
	r2 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r2.SetNextHop([]byte{10, 0, 0, 253})
	k := v4Key([4]byte{10, 0, 0, 1}, 24)
	if err := r.InstallSet(k, []*Route{r1, r2}); err != nil {
		t.Fatalf("InstallSet: %v", err)
	}

	if r.PathsLen() != 2 {
		t.Fatalf("PathsLen: got %d want 2", r.PathsLen())
	}
	if r.Len() != 1 {
		t.Fatalf("Len: got %d want 1", r.Len())
	}
	if r.Paths(k) != 2 {
		t.Fatalf("Paths: got %d want 2", r.Paths(k))
	}

	// iter_best returns 1 route (one best per key).
	n, err := r.IterBest(func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("IterBest: %v", err)
	}
	if n != 1 {
		t.Fatalf("IterBest count: got %d want 1", n)
	}

	// iter_paths returns 2 routes (every multipath entry).
	n, err = r.IterPaths(func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("IterPaths: %v", err)
	}
	if n != 2 {
		t.Fatalf("IterPaths count: got %d want 2", n)
	}

	// iter_sets returns 1 set with 2 paths.
	n, err = r.IterSets(func(entry LocRibSetEntry) {
		if entry.PrefixLen != 24 {
			t.Errorf("IterSets PrefixLen: got %d want 24", entry.PrefixLen)
		}
		if entry.IsIPv6 {
			t.Errorf("IterSets IsIPv6: true")
		}
		if entry.PathCount != 2 {
			t.Errorf("IterSets PathCount: got %d want 2", entry.PathCount)
		}
		// IPv4 address occupies the first 4 bytes of the 16-byte
		// buffer (per the C ABI iter_sets contract).
		if entry.Addr[0] != 10 || entry.Addr[1] != 0 ||
			entry.Addr[2] != 0 || entry.Addr[3] != 1 {
			t.Errorf("IterSets Addr[:4]: got %v want [10 0 0 1]",
				[]byte{entry.Addr[0], entry.Addr[1], entry.Addr[2], entry.Addr[3]})
		}
	})
	if err != nil {
		t.Fatalf("IterSets: %v", err)
	}
	if n != 1 {
		t.Fatalf("IterSets count: got %d want 1", n)
	}

	// Free the route handles (InstallSet didn't consume them).
	r1.Free()
	r2.Free()
}

func TestLocRibDiffSince(t *testing.T) {
	r, err := NewLocRib()
	if err != nil {
		t.Fatalf("NewLocRib: %v", err)
	}
	defer r.Free()

	rt1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	rt1.SetNextHop([]byte{10, 0, 0, 254})
	r.Install(rt1)
	gen1 := r.Generation()

	rt2 := v4Route(t, [4]byte{10, 0, 0, 2}, 24, ProtoBgp)
	rt2.SetNextHop([]byte{10, 0, 0, 254})
	r.Install(rt2)
	gen2 := r.Generation()
	if gen2 <= gen1 {
		t.Fatalf("Generation did not advance: %d vs %d", gen2, gen1)
	}

	diff, err := r.DiffSince(gen1 - 1)
	if err != nil {
		t.Fatalf("DiffSince: %v", err)
	}
	if diff.Added < 1 {
		t.Errorf("DiffSince added: got %d want >= 1", diff.Added)
	}

	diff, err = r.DiffSince(gen2)
	if err != nil {
		t.Fatalf("DiffSince (current): %v", err)
	}
	if diff.Added != 0 || diff.Modified != 0 || diff.Removed != 0 {
		t.Errorf("DiffSince (current): %+v want zero", diff)
	}
}

// ---- AdjRibIn ----

func TestAdjRibInLifecycle(t *testing.T) {
	r, err := NewAdjRibIn()
	if err != nil {
		t.Fatalf("NewAdjRibIn: %v", err)
	}
	defer r.Free()

	if !r.IsEmpty() {
		t.Fatalf("fresh AdjRibIn not empty")
	}
	if r.Len() != 0 {
		t.Fatalf("Len: got %d want 0", r.Len())
	}
}

func TestAdjRibInFeedWithdrawGet(t *testing.T) {
	r, err := NewAdjRibIn()
	if err != nil {
		t.Fatalf("NewAdjRibIn: %v", err)
	}
	defer r.Free()

	rt := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	origin := RouteOrigin{Protocol: ProtoBgp, Peer: 42}
	if err := r.Feed(origin, rt); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len after Feed: got %d want 1", r.Len())
	}

	k := v4Key([4]byte{10, 0, 0, 1}, 24)
	got, err := r.Get(origin, k, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("Get: nil")
	}
	defer got.Free()

	origins, err := r.OriginsFor(k)
	if err != nil {
		t.Fatalf("OriginsFor: %v", err)
	}
	if len(origins) < 1 {
		t.Fatalf("OriginsFor: empty")
	}
	found := false
	for _, o := range origins {
		if o.Protocol == ProtoBgp && o.Peer == 42 {
			found = true
		}
	}
	if !found {
		t.Errorf("OriginsFor: missing (BGP, 42)")
	}

	// Withdraw.
	ok, err := r.Withdraw(origin, k, 0)
	if err != nil || !ok {
		t.Fatalf("Withdraw: ok=%v err=%v", ok, err)
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Withdraw: got %d want 0", r.Len())
	}
	// Second Withdraw is a no-op.
	ok, err = r.Withdraw(origin, k, 0)
	if err != nil || ok {
		t.Fatalf("Withdraw (no-op): ok=%v err=%v", ok, err)
	}
}

func TestAdjRibInIterAllAndClearFor(t *testing.T) {
	r, err := NewAdjRibIn()
	if err != nil {
		t.Fatalf("NewAdjRibIn: %v", err)
	}
	defer r.Free()

	origin := RouteOrigin{Protocol: ProtoBgp, Peer: 42}
	r1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r2 := v4Route(t, [4]byte{10, 0, 0, 2}, 24, ProtoBgp)
	r.Feed(origin, r1)
	r.Feed(origin, r2)

	n, err := r.IterAll(func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("IterAll: %v", err)
	}
	if n != 2 {
		t.Fatalf("IterAll count: got %d want 2", n)
	}

	n, err = r.IterOrigin(origin, func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("IterOrigin: %v", err)
	}
	if n != 2 {
		t.Fatalf("IterOrigin count: got %d want 2", n)
	}

	if err := r.ClearFor(origin); err != nil {
		t.Fatalf("ClearFor: %v", err)
	}
	if !r.IsEmpty() {
		t.Fatalf("not empty after ClearFor")
	}
}

// ---- AdjRibOut ----

func TestAdjRibOutAdvertiseAndIter(t *testing.T) {
	out, err := NewAdjRibOut()
	if err != nil {
		t.Fatalf("NewAdjRibOut: %v", err)
	}
	defer out.Free()

	if !out.IsEmpty() {
		t.Fatalf("fresh AdjRibOut not empty")
	}

	dest := RouteOrigin{Protocol: ProtoBgp, Peer: 42}
	r := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r.SetNextHop([]byte{10, 0, 0, 254})
	if err := out.Advertise(dest, r, 100); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	// The route handle is NOT consumed.
	if err := out.Advertise(dest, r, 200); err != nil {
		t.Fatalf("Advertise (again): %v", err)
	}
	if out.Len() != 2 {
		t.Fatalf("Len: got %d want 2", out.Len())
	}
	defer r.Free()

	k := v4Key([4]byte{10, 0, 0, 1}, 24)
	ids, err := out.TxPathIDs(dest, k)
	if err != nil {
		t.Fatalf("TxPathIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("TxPathIDs: got %d want 2", len(ids))
	}
	// Sort for comparison.
	if (ids[0] == 100 && ids[1] == 200) || (ids[0] == 200 && ids[1] == 100) {
		// ok
	} else {
		t.Errorf("TxPathIDs values: got %v want {100, 200}", ids)
	}

	n, err := out.IterFor(dest, func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("IterFor: %v", err)
	}
	if n != 2 {
		t.Fatalf("IterFor count: got %d want 2", n)
	}

	// Suppress one tx_path_id.
	ok, err := out.Suppress(dest, k, 100)
	if err != nil || !ok {
		t.Fatalf("Suppress: ok=%v err=%v", ok, err)
	}
	if out.Len() != 1 {
		t.Fatalf("Len after Suppress: got %d want 1", out.Len())
	}

	// Second Suppress on the same (dest, key, tx_path_id) is a no-op.
	ok, err = out.Suppress(dest, k, 100)
	if err != nil || ok {
		t.Fatalf("Suppress (no-op): ok=%v err=%v", ok, err)
	}

	// ClearFor removes the rest.
	if err := out.ClearFor(dest); err != nil {
		t.Fatalf("ClearFor: %v", err)
	}
	if !out.IsEmpty() {
		t.Fatalf("not empty after ClearFor")
	}
}

func TestAdjRibOutPathsFor(t *testing.T) {
	out, err := NewAdjRibOut()
	if err != nil {
		t.Fatalf("NewAdjRibOut: %v", err)
	}
	defer out.Free()
	dest := RouteOrigin{Protocol: ProtoBgp, Peer: 42}
	r := v4Route(t, [4]byte{203, 0, 113, 1}, 24, ProtoBgp)
	defer r.Free()

	// Advertise the same route under three different tx_path_ids.
	for _, id := range []uint32{1, 2, 3} {
		if err := out.Advertise(dest, r, id); err != nil {
			t.Fatalf("Advertise(%d): %v", id, err)
		}
	}

	k := v4Key([4]byte{203, 0, 113, 1}, 24)
	pairs, err := out.PathsFor(dest, k)
	if err != nil {
		t.Fatalf("PathsFor: %v", err)
	}
	if len(pairs) != 3 {
		t.Fatalf("PathsFor len: got %d want 3", len(pairs))
	}
	want := []uint32{1, 2, 3}
	for i, p := range pairs {
		if p.TxPathID != want[i] {
			t.Errorf("PathsFor[%d].TxPathID: got %d want %d", i, p.TxPathID, want[i])
		}
	}

	// Unknown key returns an empty slice.
	unknown := v4Key([4]byte{10, 0, 0, 0}, 8)
	empty, err := out.PathsFor(dest, unknown)
	if err != nil {
		t.Fatalf("PathsFor (unknown): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("PathsFor (unknown): got %d want 0", len(empty))
	}
}

func TestAdjRibOutAdvertisedKeys(t *testing.T) {
	out, err := NewAdjRibOut()
	if err != nil {
		t.Fatalf("NewAdjRibOut: %v", err)
	}
	defer out.Free()
	dest := RouteOrigin{Protocol: ProtoBgp, Peer: 42}

	// v4 path.
	rV4 := v4Route(t, [4]byte{203, 0, 113, 1}, 24, ProtoBgp)
	defer rV4.Free()
	if err := out.Advertise(dest, rV4, 1); err != nil {
		t.Fatalf("Advertise (v4): %v", err)
	}

	// v6 path.
	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	rV6, err := NewRouteV6(v6, 64, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV6: %v", err)
	}
	defer rV6.Free()
	if err := out.Advertise(dest, rV6, 1); err != nil {
		t.Fatalf("Advertise (v6): %v", err)
	}

	// Filter by v4 unicast → only the v4 key.
	v4Keys, err := out.AdvertisedKeys(dest, AFIIPv4, SAFIUnicast)
	if err != nil {
		t.Fatalf("AdvertisedKeys (v4): %v", err)
	}
	if len(v4Keys) != 1 {
		t.Fatalf("AdvertisedKeys (v4): got %d want 1", len(v4Keys))
	}
	if v4Keys[0].Key.AFI != AFIIPv4 || v4Keys[0].Key.SAFI != SAFIUnicast {
		t.Errorf("AdvertisedKeys (v4) family: AFI=%d SAFI=%d want %d/%d",
			v4Keys[0].Key.AFI, v4Keys[0].Key.SAFI, AFIIPv4, SAFIUnicast)
	}
	if v4Keys[0].Key.PrefixLen != 24 {
		t.Errorf("AdvertisedKeys (v4) PrefixLen: got %d want 24", v4Keys[0].Key.PrefixLen)
	}
	if len(v4Keys[0].TxPathID) != 1 || v4Keys[0].TxPathID[0] != 1 {
		t.Errorf("AdvertisedKeys (v4) TxPathID: got %v want [1]", v4Keys[0].TxPathID)
	}

	// Filter by v6 unicast → only the v6 key.
	v6Keys, err := out.AdvertisedKeys(dest, AFIIPv6, SAFIUnicast)
	if err != nil {
		t.Fatalf("AdvertisedKeys (v6): %v", err)
	}
	if len(v6Keys) != 1 {
		t.Fatalf("AdvertisedKeys (v6): got %d want 1", len(v6Keys))
	}
	if v6Keys[0].Key.AFI != AFIIPv6 {
		t.Errorf("AdvertisedKeys (v6) AFI: got %d want %d", v6Keys[0].Key.AFI, AFIIPv6)
	}
	if v6Keys[0].Key.PrefixLen != 64 {
		t.Errorf("AdvertisedKeys (v6) PrefixLen: got %d want 64", v6Keys[0].Key.PrefixLen)
	}

	// Wrong dest peer → empty.
	wrong := RouteOrigin{Protocol: ProtoBgp, Peer: 99}
	wrongKeys, err := out.AdvertisedKeys(wrong, AFIIPv4, SAFIUnicast)
	if err != nil {
		t.Fatalf("AdvertisedKeys (wrong): %v", err)
	}
	if len(wrongKeys) != 0 {
		t.Fatalf("AdvertisedKeys (wrong): got %d want 0", len(wrongKeys))
	}

	// Labelled-unicast filter → empty (we did not advertise any).
	labeledKeys, err := out.AdvertisedKeys(dest, AFIIPv4, SAFILabeledUni)
	if err != nil {
		t.Fatalf("AdvertisedKeys (labeled): %v", err)
	}
	if len(labeledKeys) != 0 {
		t.Fatalf("AdvertisedKeys (labeled): got %d want 0", len(labeledKeys))
	}
}

// ---- RibMux ----

func TestRibMuxInstallGetUninstall(t *testing.T) {
	m, err := NewRibMux()
	if err != nil {
		t.Fatalf("NewRibMux: %v", err)
	}
	defer m.Free()

	if !m.IsEmpty() {
		t.Fatalf("fresh RibMux not empty")
	}

	r := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r.SetNextHop([]byte{10, 0, 0, 254})
	if err := m.Install(r); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("Len: got %d want 1", m.Len())
	}

	k := v4Key([4]byte{10, 0, 0, 1}, 24)
	got, err := m.Get(k)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("Get: nil")
	}
	defer got.Free()

	// Uninstall.
	ok, err := m.Uninstall(k)
	if err != nil || !ok {
		t.Fatalf("Uninstall: ok=%v err=%v", ok, err)
	}
	if !m.IsEmpty() {
		t.Fatalf("not empty after Uninstall")
	}
	// Second Uninstall is a no-op.
	ok, err = m.Uninstall(k)
	if err != nil || ok {
		t.Fatalf("Uninstall (no-op): ok=%v err=%v", ok, err)
	}
}

func TestRibMuxIter(t *testing.T) {
	m, err := NewRibMux()
	if err != nil {
		t.Fatalf("NewRibMux: %v", err)
	}
	defer m.Free()

	// Empty mux → Iter walks nothing.
	n, err := m.Iter(func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("Iter (empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("Iter (empty): got %d want 0", n)
	}

	// Install two routes under different keys so both survive.
	r1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	defer r1.Free()
	if err := m.Install(r1); err != nil {
		t.Fatalf("Install(r1): %v", err)
	}
	r2 := v4Route(t, [4]byte{10, 0, 1, 1}, 24, ProtoBgp)
	defer r2.Free()
	if err := m.Install(r2); err != nil {
		t.Fatalf("Install(r2): %v", err)
	}
	if m.Len() != 2 {
		t.Fatalf("Len: got %d want 2", m.Len())
	}

	// Iter walks both merged routes.
	n, err = m.Iter(func(rt BorrowedRoute) {})
	if err != nil {
		t.Fatalf("Iter: %v", err)
	}
	if n != 2 {
		t.Fatalf("Iter: got %d want 2", n)
	}
}

// ---- RouteSelector ----

func TestRouteSelectorSelect(t *testing.T) {
	r1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r1.SetNextHop([]byte{10, 0, 0, 254})
	defer r1.Free()
	r2 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	r2.SetNextHop([]byte{10, 0, 0, 253})
	defer r2.Free()

	rs := RouteSelector{}
	idx := rs.Select([]*Route{r1, r2})
	if idx != 0 && idx != 1 {
		t.Fatalf("Select: got %d want 0 or 1", idx)
	}

	idxBgp := rs.SelectBGP([]*Route{r1, r2})
	if idxBgp != 0 && idxBgp != 1 {
		t.Fatalf("SelectBGP: got %d want 0 or 1", idxBgp)
	}

	// Empty slice returns -1.
	if got := rs.Select(nil); got != -1 {
		t.Errorf("Select (empty): got %d want -1", got)
	}
	if got := rs.SelectBGP(nil); got != -1 {
		t.Errorf("SelectBGP (empty): got %d want -1", got)
	}
}

func TestRouteSelectorCompare(t *testing.T) {
	r1 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	defer r1.Free()
	r2 := v4Route(t, [4]byte{10, 0, 0, 1}, 24, ProtoBgp)
	defer r2.Free()
	rs := RouteSelector{}

	// Two equal-default routes tie on every discriminator.
	rc, err := rs.Compare(r1, r2)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if rc < -1 || rc > 1 {
		t.Fatalf("Compare: got %d want -1..1", rc)
	}

	// Anti-symmetric: swapping args mirrors the result.
	rc2, err := rs.Compare(r2, r1)
	if err != nil {
		t.Fatalf("Compare (swap): %v", err)
	}
	if rc != -rc2 && rc != 0 {
		t.Errorf("Compare anti-symmetry: %d vs swapped %d", rc, rc2)
	}

	// Identical routes compare equal.
	rc3, err := rs.Compare(r1, r1)
	if err != nil {
		t.Fatalf("Compare (self): %v", err)
	}
	if rc3 != 0 {
		t.Errorf("Compare (self): got %d want 0", rc3)
	}
}

func TestRouteKeyAndRouteOrigin(t *testing.T) {
	k := RouteKey{
		Addr:      []byte{10, 0, 0, 1},
		PrefixLen: 24,
		AFI:       AFIIPv4,
		SAFI:      SAFIUnicast,
		Source:    []byte{10, 0, 0, 2},
		SourceLen: 32,
	}
	// Smoke-test the toC helper — the structured lr_route_key_t layout
	// is exercised by the InstallSet round-trip below.
	ck := k.toC()
	if ck.prefix.prefix_len != 24 {
		t.Errorf("RouteKey.toC: prefix_len=%d want 24", ck.prefix.prefix_len)
	}
	if ck.afi_safi != (1<<8)|1 {
		t.Errorf("RouteKey.toC: afi_safi=%d want %d", ck.afi_safi, (1<<8)|1)
	}
	if ck.has_source != 1 {
		t.Errorf("RouteKey.toC: has_source=%d want 1", ck.has_source)
	}

	o := RouteOrigin{Protocol: ProtoOspf, Peer: 99}
	if o.Protocol != ProtoOspf || o.Peer != 99 {
		t.Errorf("RouteOrigin round-trip: %+v", o)
	}
}

func TestIPv6LocRibInstallAndBest(t *testing.T) {
	r, err := NewLocRib()
	if err != nil {
		t.Fatalf("NewLocRib: %v", err)
	}
	defer r.Free()

	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	rt, err := NewRouteV6(v6, 64, ProtoBgp)
	if err != nil {
		t.Fatalf("NewRouteV6: %v", err)
	}
	if changed, err := r.Install(rt); err != nil || !changed {
		t.Fatalf("Install (v6): changed=%v err=%v", changed, err)
	}

	k := RouteKey{
		Addr:      v6[:],
		PrefixLen: 64,
		AFI:       AFIIPv6,
		SAFI:      SAFIUnicast,
	}
	if !r.BestPresent(k) {
		t.Fatalf("BestPresent (v6): false")
	}
	best, err := r.Best(k)
	if err != nil {
		t.Fatalf("Best (v6): %v", err)
	}
	if best == nil {
		t.Fatalf("Best (v6): nil")
	}
	defer best.Free()
}
