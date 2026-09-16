package main

import "debug/elf"

// The four hardening properties, split into pure helpers so they can be
// unit-tested against synthetic elf.File values without touching the disk.

// hasPIE reports whether the image is position-independent. A PIE is an
// ET_DYN object; the DF_1_PIE flag distinguishes it from a plain shared
// library, with the presence of a PT_INTERP segment as the fallback signal
// for toolchains that do not emit the flag.
func hasPIE(f *elf.File) bool {
	if f.Type != elf.ET_DYN {
		return false
	}
	if vals, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_1_PIE) != 0 {
				return true
			}
		}
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}

// hasNX reports whether the stack is non-executable. The second return value
// is false when the image carries no PT_GNU_STACK segment at all, in which
// case the kernel default applies and we cannot answer from the file alone.
func hasNX(f *elf.File) (nx bool, known bool) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_STACK {
			return p.Flags&elf.PF_X == 0, true
		}
	}
	return false, false
}

// bindNow reports whether the dynamic loader is asked to resolve every
// relocation eagerly, which is what promotes partial RELRO to full RELRO.
func bindNow(f *elf.File) bool {
	if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		return true
	}
	if vals, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_BIND_NOW) != 0 {
				return true
			}
		}
	}
	if vals, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_1_NOW) != 0 {
				return true
			}
		}
	}
	return false
}

// relroLevel returns "none", "partial" or "full".
func relroLevel(f *elf.File) string {
	var found bool
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			found = true
			break
		}
	}
	if !found {
		return "none"
	}
	if bindNow(f) {
		return "full"
	}
	return "partial"
}

// hasCanary looks for the stack-protector runtime symbols. They survive in
// the dynamic symbol table even in stripped binaries, which is why both
// tables are consulted.
func hasCanary(f *elf.File) bool {
	var syms []elf.Symbol
	if s, err := f.DynamicSymbols(); err == nil {
		syms = append(syms, s...)
	}
	if s, err := f.Symbols(); err == nil {
		syms = append(syms, s...)
	}
	for _, s := range syms {
		if s.Name == "__stack_chk_fail" || s.Name == "__stack_chk_guard" {
			return true
		}
	}
	return false
}
