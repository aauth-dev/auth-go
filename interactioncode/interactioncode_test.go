package interactioncode

import (
	"strings"
	"testing"
)

func TestGenerateFormat(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("bad format %q", c)
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("char %q outside Crockford alphabet in %q", r, c)
			}
		}
		if seen[c] {
			t.Fatalf("duplicate code %q in 100 draws", c)
		}
		seen[c] = true
	}
}

func TestCanonicalize(t *testing.T) {
	got, err := Canonicalize("a1b2-c3d4")
	if err != nil || got != "A1B2-C3D4" {
		t.Fatalf("got %q, %v", got, err)
	}
	// Lookalike folding: i/l → 1, o → 0; separators stripped.
	got, err = Canonicalize(" oIb2 c3dl ")
	if err != nil || got != "01B2-C3D1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := Canonicalize("A1B2-C3"); err == nil {
		t.Fatal("short code accepted")
	}
	if _, err := Canonicalize("A1B2-C3DU"); err == nil {
		t.Fatal("U accepted")
	}
}
