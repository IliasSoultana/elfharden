package main

import (
	"debug/elf"
	"testing"
)

// prog builds a synthetic program header so the checks can be exercised
// without needing real binaries on disk.
func prog(t elf.ProgType, flags elf.ProgFlag) *elf.Prog {
	return &elf.Prog{ProgHeader: elf.ProgHeader{Type: t, Flags: flags}}
}

func TestHasNX(t *testing.T) {
	tests := []struct {
		name      string
		progs     []*elf.Prog
		wantNX    bool
		wantKnown bool
	}{
		{"no GNU_STACK segment", nil, false, false},
		{"writable non-exec stack", []*elf.Prog{prog(elf.PT_GNU_STACK, elf.PF_R|elf.PF_W)}, true, true},
		{"executable stack", []*elf.Prog{prog(elf.PT_GNU_STACK, elf.PF_R|elf.PF_W|elf.PF_X)}, false, true},
		{"unrelated segment only", []*elf.Prog{prog(elf.PT_LOAD, elf.PF_R)}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nx, known := hasNX(&elf.File{Progs: tc.progs})
			if nx != tc.wantNX || known != tc.wantKnown {
				t.Errorf("hasNX() = (%v, %v), want (%v, %v)", nx, known, tc.wantNX, tc.wantKnown)
			}
		})
	}
}

func TestRelroLevel(t *testing.T) {
	tests := []struct {
		name  string
		progs []*elf.Prog
		want  string
	}{
		{"no RELRO segment", nil, "none"},
		// Without a dynamic section DynValue reports an error, so BIND_NOW
		// cannot be established and the level stays partial.
		{"RELRO without bind-now", []*elf.Prog{prog(elf.PT_GNU_RELRO, elf.PF_R)}, "partial"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := relroLevel(&elf.File{Progs: tc.progs}); got != tc.want {
				t.Errorf("relroLevel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHasPIE(t *testing.T) {
	tests := []struct {
		name  string
		typ   elf.Type
		progs []*elf.Prog
		want  bool
	}{
		{"static executable", elf.ET_EXEC, nil, false},
		{"relocatable object", elf.ET_REL, nil, false},
		{"shared library, no interpreter", elf.ET_DYN, nil, false},
		{"PIE with interpreter", elf.ET_DYN, []*elf.Prog{prog(elf.PT_INTERP, elf.PF_R)}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{FileHeader: elf.FileHeader{Type: tc.typ}, Progs: tc.progs}
			if got := hasPIE(f); got != tc.want {
				t.Errorf("hasPIE() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportHardened(t *testing.T) {
	base := Report{PIE: true, NX: "yes", Canary: true, RELRO: "full"}
	if !base.hardened() {
		t.Fatal("fully hardened report should pass policy")
	}

	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"not PIE", func(r *Report) { r.PIE = false }},
		{"executable stack", func(r *Report) { r.NX = "no" }},
		{"unknown stack flags", func(r *Report) { r.NX = "unknown" }},
		{"no canary", func(r *Report) { r.Canary = false }},
		{"partial RELRO", func(r *Report) { r.RELRO = "partial" }},
		{"read error", func(r *Report) { r.Error = "not an ELF file" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			if r.hardened() {
				t.Errorf("%s should fail policy", tc.name)
			}
		})
	}
}
