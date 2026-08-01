package lanid

import (
	"os"
	"testing"
)

// TestMain points os.UserConfigDir at a temp dir so the package's identity /
// trust / settings / activity files are written under the test's HOME, not the
// developer's real config. (os.UserConfigDir uses XDG_CONFIG_HOME on Linux and
// HOME elsewhere.)
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lanid-test-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("HOME", dir)
	os.Setenv("AppData", dir) // windows
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestIdentityStableAndFingerprinted(t *testing.T) {
	k1, err := Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	k2, _ := Identity()
	if string(k1) != string(k2) {
		t.Fatal("Identity not stable across calls")
	}
	if Fingerprint() == "" {
		t.Fatal("empty fingerprint")
	}
	if Code() == "" {
		t.Fatal("empty verify code")
	}
}

func TestTrustRoundTrip(t *testing.T) {
	const fp, name = "abc123fingerprint", "Alice's laptop"
	if _, ok := Lookup(fp); ok {
		t.Fatal("unexpectedly trusted before Trust")
	}
	if err := Trust(fp, name); err != nil {
		t.Fatalf("Trust: %v", err)
	}
	d, ok := Lookup(fp)
	if !ok || d.Name != name {
		t.Fatalf("Lookup after Trust = %+v, %v", d, ok)
	}
	if got := List(); len(got) != 1 || got[0].Fingerprint != fp {
		t.Fatalf("List = %+v", got)
	}
	// empty fingerprint is never trusted
	if _, ok := Lookup(""); ok {
		t.Fatal("empty fingerprint reported trusted")
	}
	if err := Untrust(fp); err != nil {
		t.Fatalf("Untrust: %v", err)
	}
	if _, ok := Lookup(fp); ok {
		t.Fatal("still trusted after Untrust")
	}
}

func TestScanIntervalAndActivity(t *testing.T) {
	if GetScanInterval() != defaultScanIntervalSec {
		t.Fatalf("default scan interval = %d", GetScanInterval())
	}
	if err := SetScanInterval(5); err != nil {
		t.Fatalf("SetScanInterval: %v", err)
	}
	if GetScanInterval() != 5 {
		t.Fatalf("scan interval not persisted = %d", GetScanInterval())
	}

	ActivityClear()
	ActivityAppend(ActivityEntry{Kind: "broadcast", Peer: "p1", Name: "a.txt", Size: 10})
	ActivityAppend(ActivityEntry{Kind: "downloaded", Peer: "p2", Name: "b.txt", Size: 20})
	list := ActivityList()
	if len(list) != 2 || list[0].Kind != "downloaded" { // newest first
		t.Fatalf("ActivityList = %+v", list)
	}
	if list[0].TS == 0 {
		t.Fatal("activity timestamp not set")
	}
	ActivityClear()
	if len(ActivityList()) != 0 {
		t.Fatal("activity not cleared")
	}
}
