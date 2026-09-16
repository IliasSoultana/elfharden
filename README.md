# elfharden

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
filter — it can read binaries and write one report, and nothing else.

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
2. **A Linux VM** — UTM, Lima or OrbStack, then build inside it.
3. **nix-darwin's `linux-builder`** — `nix.linux-builder.enable = true` gives
   Nix a local Linux VM to delegate Linux derivations to.

## CI

`.github/workflows/ci.yml` runs two jobs on every push:

- **go** — `go vet`, `go test`, `go build`, then a smoke test scanning the
  runner's own `/usr/bin` so the parser is exercised against real production
  binaries rather than only synthetic fixtures.
- **nix** — `nix flake check --all-systems`, builds the package, builds the
  qcow2 image, and uploads it as a workflow artifact.

A green run on that second job is what makes the phrase "reproducible NixOS
system image" true.
