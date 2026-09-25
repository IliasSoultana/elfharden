# elfharden

[![CI](https://github.com/IliasSoultana/elfharden/actions/workflows/ci.yml/badge.svg)](https://github.com/IliasSoultana/elfharden/actions/workflows/ci.yml)

Scans ELF binaries for the four standard hardening properties and reports them
as a table or as JSON.

This is a Go rewrite of [hardening-check](https://github.com/IliasSoultana/hardening-check).
The Python version analyses one binary at a time; this one walks whole
directory trees with a bounded worker pool and can fail a CI job on any binary
that does not meet policy.

## What is checked

| Property | How it is detected |
| --- | --- |
| **PIE** | `ET_DYN` image carrying `DF_1_PIE`, or a `PT_INTERP` segment as fallback |
| **NX** | `PT_GNU_STACK` present without the `PF_X` bit |
| **Stack canary** | `__stack_chk_fail` / `__stack_chk_guard` in either symbol table |
| **RELRO** | `PT_GNU_RELRO` present; *full* when `BIND_NOW` is also set, else *partial* |

`NX` reports `unknown` when the image carries no `PT_GNU_STACK` segment at all,
since the kernel default then applies and the file alone cannot answer.

## Build

```
go build -o elfharden .
```

No third-party dependencies: parsing is handled by the `debug/elf` standard
library package.

## Usage

```
elfharden [flags] <file-or-directory>...

  -json       emit JSON instead of a table
  -strict     exit 1 if any binary fails the hardening policy
  -verbose    include unreadable/non-ELF files in table output
  -workers N  number of concurrent workers (default: NumCPU)
```

Scan a directory tree:

```
$ elfharden /usr/bin
BINARY           PIE  NX   CANARY  RELRO
/usr/bin/ls      yes  yes  yes     full
/usr/bin/ssh     yes  yes  yes     full
/usr/bin/legacy  no   yes  no      partial
```

Gate a build in CI:

```
$ elfharden -strict build/
$ echo $?
1
```

JSON for downstream tooling:

```
$ elfharden -json /usr/bin/ls
[
  {
    "path": "/usr/bin/ls",
    "pie": true,
    "nx": "yes",
    "canary": true,
    "relro": "full"
  }
]
```

Non-ELF files are skipped silently when walking a directory, so pointing the
tool at a mixed build output directory is safe. Pass `-verbose` to list them.

## Tests

```
go test ./...
```

The hardening checks are pure functions over `*elf.File`, so the table-driven
tests construct synthetic ELF headers and need no fixture binaries.

## Reproducible NixOS image

The repository is also a Nix flake. It packages the scanner and builds a
minimal bootable image that runs it as a sandboxed systemd service on a timer.

```
nix build .#elfharden          # just the binary
nix build .#image              # bootable qcow2
nix develop                    # Go toolchain + qemu shell
```

The service runs under `DynamicUser` with `ProtectSystem=strict`,
`PrivateNetwork`, `MemoryDenyWriteExecute` and a `@system-service` syscall
filter, it can read binaries and write one report, and nothing else.

Configure it through the module options:

```nix
services.elfharden = {
  enable = true;
  paths = [ "/run/current-system/sw/bin" "/opt/vendor" ];
  interval = "hourly";
};
```

Add an SSH key to `nixos/configuration.nix` before building the image.

### Building on macOS

`nix build .#elfharden` and `nix develop` work on Darwin. `nix build .#image`
does not: producing a NixOS disk image requires a Linux builder. Three ways
around it, cheapest first:

1. **Let CI do it.** `.github/workflows/ci.yml` builds the scanner and the
   qcow2 image on `ubuntu-latest` and uploads the image as an artifact. Push
   the branch and read the logs.
2. **A Linux VM** (UTM, Lima or OrbStack), then build inside it.
3. **nix-darwin's `linux-builder`**, `nix.linux-builder.enable = true` gives
   Nix a local Linux VM to delegate Linux derivations to.

## CI

`.github/workflows/ci.yml` runs two jobs on every push:

- **go**, `go vet`, `go test`, `go build`, then a smoke test scanning the
  runner's own `/usr/bin` so the parser is exercised against real production
  binaries rather than only synthetic fixtures.
- **nix**, `nix flake check --all-systems`, builds the package, builds the
  qcow2 image, and uploads it as a workflow artifact.

A green run on that second job is what makes the phrase "reproducible NixOS
system image" true.

## Reproducible, integrity-protected image

`nix build .#verity-image` produces a disk image whose root filesystem is
read-only erofs, protected by a dm-verity Merkle tree, and assembled with
`systemd-repart` rather than by booting a VM.

```
$ nix build .#verity-image -o result-verity
$ grep roothash result-verity/repart-output.json
"roothash" : "7a19e4ce445f6be65bccee001c4d128c70b643088de8be4a4f5b38f46b563148"
```

That root hash is the image's identity: it fixes every byte of the root
filesystem, so any modification is detectable at read time.

A hash is only a useful identity if the build is reproducible, otherwise it
identifies one build machine rather than one set of sources. Two details in
[`nixos/image-repart.nix`](nixos/image-repart.nix) secure that:

- partition `UUID`s are pinned rather than generated,
- `mkfs.erofs` runs with `--hard-dereference`, so a Nix store with hardlink
  optimisation enabled yields the same inode count as one without it.

Verify it:

```
$ nix build .#verity-image --rebuild
checking outputs of '/nix/store/...-elfharden-1.drv'...
$ echo $?
0
```

`--rebuild` builds the derivation a second time and compares the result
byte-for-byte. Exit code 0 means the two builds are identical.

This target needs no KVM, so it builds inside a VM on Apple Silicon, where
`.#image` (qcow2) cannot. On Ubuntu hosts, `systemd-repart` needs nested user
namespaces: `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

The approach follows Contrast's pod-VM images
([`packages/nixos/image.nix`](https://github.com/edgelesssys/contrast/blob/main/packages/nixos/image.nix)),
which uses the same repart, erofs and dm-verity combination for the same reason.

## Related

The same scanner, and the same question asked at other stages:

- [hardening-check](https://github.com/IliasSoultana/hardening-check) - Python, `pyelftools`
- [elfharden](https://github.com/IliasSoultana/elfharden) - Go, `debug/elf`
- [elfharden-rs](https://github.com/IliasSoultana/elfharden-rs) - Rust, `goblin`
- [llvm-hardeningpass](https://github.com/IliasSoultana/llvm-hardeningpass) - at IR level, before linking
- [diversity-poc](https://github.com/IliasSoultana/diversity-poc) - compiler-level layout diversification
