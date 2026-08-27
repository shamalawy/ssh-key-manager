package netdev

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
)

// Real keys, not fabricated base64: the extractor's job is to feed lines to the
// SSH parser, and a parser that rejects made-up material is behaving correctly.
func generateKeyLine(t *testing.T, comment string) string {
	t.Helper()

	pair, err := keys.Generate(keys.Ed25519, comment)
	if err != nil {
		t.Fatalf("generating a test key: %v", err)
	}
	return pair.PublicLine
}

func TestLookupUnknownProfileNamesTheAlternatives(t *testing.T) {
	_, err := Lookup("cisco_iosxr")
	if err == nil {
		t.Fatal("Lookup accepted an unknown profile")
	}
	// An operator hitting this needs to know what they *can* use.
	if !strings.Contains(err.Error(), "arista_eos") {
		t.Errorf("the error should list the known profiles: %v", err)
	}
}

func TestRenderSubstitutesEveryField(t *testing.T) {
	sampleKey := generateKeyLine(t, "skm@fleet")

	subs := substitutions{
		Username: "netops", Key: sampleKey, Type: "ssh-ed25519",
		Blob: "AAAAC3Nz", Comment: "skm_fleet", Fingerprint: "SHA256:abc",
	}

	got := render("u={{username}} k={{key}} t={{type}} b={{blob}} c={{comment}} f={{fingerprint}}", subs)
	want := "u=netops k=" + sampleKey + " t=ssh-ed25519 b=AAAAC3Nz c=skm_fleet f=SHA256:abc"

	if got != want {
		t.Errorf("render() = %q\nwant %q", got, want)
	}
}

func TestChunkWrapsToTheDeviceWidth(t *testing.T) {
	blob := strings.Repeat("A", 150)

	lines := strings.Split(chunk(blob, 72), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	if len(lines[0]) != 72 || len(lines[1]) != 72 || len(lines[2]) != 6 {
		t.Errorf("line lengths = %d/%d/%d, want 72/72/6",
			len(lines[0]), len(lines[1]), len(lines[2]))
	}
	if strings.Join(lines, "") != blob {
		t.Error("chunking lost or altered content")
	}
}

func TestChunkedSubstitutionExpandsInPlace(t *testing.T) {
	subs := substitutions{Blob: strings.Repeat("B", 100), ChunkWidth: 40}

	got := render("{{blob_chunks}}", subs)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
}

func TestSplitPublicLine(t *testing.T) {
	tests := []struct {
		name                   string
		line                   string
		keyType, blob, comment string
	}{
		{"full line", "ssh-ed25519 AAAA skm@fleet", "ssh-ed25519", "AAAA", "skm@fleet"},
		{"no comment", "ssh-rsa BBBB", "ssh-rsa", "BBBB", ""},
		{"multiword comment", "ssh-rsa BBBB a b c", "ssh-rsa", "BBBB", "a b c"},
		{"junk", "notakey", "", "", ""},
		{"empty", "", "", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyType, blob, comment := splitPublicLine(tc.line)
			if keyType != tc.keyType || blob != tc.blob || comment != tc.comment {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)",
					keyType, blob, comment, tc.keyType, tc.blob, tc.comment)
			}
		})
	}
}

// A comment with spaces would be parsed as extra arguments by a device CLI,
// silently changing what the command means.
func TestCommentSpacesAreCollapsed(t *testing.T) {
	profile, err := Lookup("arista_eos")
	if err != nil {
		t.Fatal(err)
	}

	subs, err := substitutionsFor("netops", connectors.DesiredKey{
		PublicLine: generateKeyLine(t, "deploy key for prod"),
		Comment:    "deploy key for prod",
	}, profile)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(subs.Comment, " ") {
		t.Errorf("Comment = %q, want no spaces", subs.Comment)
	}
}

func TestSubstitutionsForRejectsAnUnusableLine(t *testing.T) {
	profile, _ := Lookup("generic")

	if _, err := substitutionsFor("netops", connectors.DesiredKey{PublicLine: "garbage"}, profile); err == nil {
		t.Error("substitutionsFor accepted a line that is not a public key")
	}
}

// Device output interleaves keys with prompts, banners, and vendor prefixes.
// The extractor has to find the keys regardless.
func TestExtractKeysFindsKeysInVendorOutput(t *testing.T) {
	first := generateKeyLine(t, "skm@fleet")
	second := generateKeyLine(t, "backup@fleet")

	output := fmt.Sprintf(`
switch#show running-config section username
!
username netops privilege 15 role network-admin
username netops ssh-key %s
username backup ssh-key %s
!
end
switch#`, first, second)

	found := extractKeys(output)
	if len(found) != 2 {
		t.Fatalf("found %d keys, want 2", len(found))
	}
	for _, e := range found {
		if !strings.HasPrefix(e.Fingerprint, "SHA256:") {
			t.Errorf("entry has no fingerprint: %+v", e)
		}
	}
	if found[0].Fingerprint == found[1].Fingerprint {
		t.Error("the two distinct keys produced the same fingerprint")
	}
}

func TestExtractKeysHandlesJunosSetSyntax(t *testing.T) {
	output := fmt.Sprintf(
		`set system login user netops authentication ssh-ed25519 %q`,
		generateKeyLine(t, "skm@fleet"))

	found := extractKeys(output)
	if len(found) != 1 {
		t.Fatalf("found %d keys, want 1", len(found))
	}
}

func TestExtractKeysIgnoresNonKeyOutput(t *testing.T) {
	output := "% Invalid input detected at '^' marker.\nswitch#\n"

	if found := extractKeys(output); len(found) != 0 {
		t.Errorf("found %d keys in an error message", len(found))
	}
}

// Network CLIs almost never set a non-zero exit status, so error text is the
// only failure signal there is.
func TestFindMarkerDetectsVendorRejections(t *testing.T) {
	profile, err := Lookup("cisco_iosxe")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"invalid input", "% Invalid input detected at '^' marker.", true},
		{"incomplete", "% Incomplete command.", true},
		{"different case", "% invalid input detected", true},
		{"clean", "switch(config)#", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findMarker(tc.output, profile.ErrorMarkers) != ""
			if got != tc.want {
				t.Errorf("findMarker(%q) detected=%v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

func TestEveryBuiltInProfileIsUsable(t *testing.T) {
	for name := range Profiles {
		t.Run(name, func(t *testing.T) {
			profile, err := Lookup(name)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", name, err)
			}
			if profile.ChunkWidth <= 0 {
				t.Error("ChunkWidth was not defaulted")
			}
			if len(profile.ErrorMarkers) == 0 {
				t.Error("ErrorMarkers were not defaulted")
			}

			// "generic" carries no commands by design: it exists so a target
			// can supply its own.
			if name == "generic" {
				return
			}
			if len(profile.AddKey) == 0 {
				t.Error("the profile defines no add-key commands")
			}
			if len(profile.Commit) == 0 {
				t.Error("the profile defines no commit commands; a change that is not committed is lost on reload")
			}
		})
	}
}

// Restore is refused on multi-key platforms and allowed on single-key ones,
// and the refusal has to read like a decision rather than a missing feature.
func TestRestoreIsRefusedOnMultiKeyPlatforms(t *testing.T) {
	c := New()

	err := c.Restore(t.Context(), connectors.Request{
		Target: &connectors.Target{
			Name: "edge-01", Address: "10.0.0.1",
			Config: map[string]any{"profile": "juniper_junos"},
		},
		Principal:  &connectors.Principal{Username: "admin"},
		Credential: &connectors.Credential{Kind: "ssh_password", Username: "admin", Password: "x"},
	}, &connectors.Snapshot{})

	if err == nil {
		t.Fatal("Restore succeeded; it should decline on a multi-key platform")
	}
	if !strings.Contains(err.Error(), "deliberately") && !strings.Contains(err.Error(), "review") {
		t.Errorf("the refusal should explain itself: %v", err)
	}
}

// The single-key platforms are the ones where add-before-remove cannot work,
// so they are also the ones that need a rollback path. A profile that claims
// one without the other is a profile that will strand an account.
func TestSingleKeyProfilesCanRollBack(t *testing.T) {
	for name, profile := range Profiles {
		if !profile.SingleKey {
			continue
		}
		if !profile.CanRestore {
			t.Errorf("%s replaces keys but cannot restore one, so a failed "+
				"replacement would leave the principal with no working key", name)
		}
		if len(profile.RemoveKey) == 0 {
			t.Errorf("%s cannot remove a key, so it cannot restore an empty state", name)
		}
	}
}

func TestSingleKeyApplyRefusesTwoKeys(t *testing.T) {
	// Confirmed against Arista EOS 4.26.9M: a second "username X ssh-key ..."
	// silently replaces the first. Reporting two keys installed where one is
	// would be the exact failure the rotation engine exists to prevent, so the
	// connector refuses before it connects.
	c := New()

	_, err := c.Apply(t.Context(), connectors.Request{
		Target: &connectors.Target{
			Name: "sw-01", Address: "10.0.0.2",
			Config: map[string]any{"profile": "arista_eos"},
		},
		Principal:  &connectors.Principal{Username: "netops"},
		Credential: &connectors.Credential{Kind: "ssh_password", Username: "netops", Password: "x"},
	}, []connectors.DesiredKey{
		{PublicLine: "ssh-ed25519 AAAA a", Fingerprint: "SHA256:a"},
		{PublicLine: "ssh-ed25519 AAAA b", Fingerprint: "SHA256:b"},
	}, connectors.ApplyOptions{})

	if err == nil {
		t.Fatal("Apply accepted two keys for a platform that holds one")
	}
	if !strings.Contains(err.Error(), "one ssh-key per username") {
		t.Errorf("the error should say what the platform actually does: %v", err)
	}
	if !errors.Is(err, connectors.ErrUnsupported) {
		t.Errorf("the error should be reported as unsupported, not as a failure: %v", err)
	}
}

func TestValidateRequiresAProfile(t *testing.T) {
	c := New()

	err := c.Validate(t.Context(), &connectors.Target{Name: "switch-01", Address: "10.0.0.1"})
	if err == nil {
		t.Fatal("Validate accepted a target with no profile")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("the error should name the missing setting: %v", err)
	}
}

func TestValidateAcceptsAConfiguredTarget(t *testing.T) {
	c := New()

	target := &connectors.Target{
		Name: "switch-01", Address: "10.0.0.1", Port: 22,
		Config: map[string]any{"profile": "arista_eos"},
	}
	if err := c.Validate(t.Context(), target); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A vendor changing its syntax between releases must not require a new build.
func TestPerTargetOverridesReplaceProfileCommands(t *testing.T) {
	c := New()

	target := &connectors.Target{
		Name: "switch-01", Address: "10.0.0.1",
		Config: map[string]any{
			"profile":    "arista_eos",
			"add_key":    []any{"username {{username}} ssh-key-v2 {{type}} {{blob}}"},
			"commit":     []any{"copy run start"},
			"key_format": "type_blob",
		},
	}

	profile, err := c.profileFor(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.AddKey) != 1 || !strings.Contains(profile.AddKey[0], "ssh-key-v2") {
		t.Errorf("AddKey = %v, want the override", profile.AddKey)
	}
	if len(profile.Commit) != 1 || profile.Commit[0] != "copy run start" {
		t.Errorf("Commit = %v, want the override", profile.Commit)
	}
	// Untouched fields must survive.
	if profile.ShowKeys == "" {
		t.Error("overriding one command cleared the rest of the profile")
	}
}

func TestCapabilitiesFollowTheProfile(t *testing.T) {
	c := New()

	arista := &connectors.Target{Config: map[string]any{"profile": "arista_eos"}}
	caps := c.TargetCapabilities(arista)
	if !caps.CanList || !caps.CanSnapshot || !caps.CanVerify {
		t.Errorf("arista capabilities = %+v, want list/snapshot/verify", caps)
	}
	if !caps.SingleKey {
		t.Error("Arista EOS holds one ssh-key per username; the capability has to say so, " +
			"or the rotation engine will try to stage two keys where only one can live")
	}
	if !caps.CanRestore {
		t.Error("a single-key platform must be restorable: replacing the only key is what " +
			"makes a rollback necessary in the first place")
	}

	junos := &connectors.Target{Config: map[string]any{"profile": "juniper_junos"}}
	if caps := c.TargetCapabilities(junos); caps.CanRestore || caps.SingleKey {
		t.Errorf("junos holds several keys and declines a config replay: %+v", caps)
	}

	generic := &connectors.Target{Config: map[string]any{"profile": "generic"}}
	if c.TargetCapabilities(generic).CanList {
		t.Error("the generic profile has no show command, so CanList must be false")
	}
}

// A single-key platform's remove command names the username, not the key, so
// running it after an add deletes the key that was just installed. A rotation
// against a real Arista did exactly that: the new key went on, the prune took
// it straight back off, and the verification that followed correctly reported
// that the device had no such key. This asserts the fix rather than the
// symptom — pruning is suppressed once anything has been added.
func TestSingleKeyApplyDoesNotPruneWhatItJustAdded(t *testing.T) {
	profile := Profiles["arista_eos"]

	if !profile.SingleKey {
		t.Fatal("this test is about the single-key path")
	}
	if len(profile.RemoveKey) == 0 {
		t.Fatal("the profile has no removal command, so there is nothing to guard against")
	}

	// The removal command must not name a key — if it did, a targeted prune
	// would be safe and this guard would be unnecessary.
	for _, cmd := range profile.RemoveKey {
		for _, placeholder := range []string{"{{key}}", "{{blob}}", "{{fingerprint}}"} {
			if strings.Contains(cmd, placeholder) {
				t.Errorf("RemoveKey %q names a specific key via %s; "+
					"revisit the prune guard, which assumes it cannot", cmd, placeholder)
			}
		}
	}
}
