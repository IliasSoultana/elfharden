{
  description = "elfharden - ELF hardening scanner, packaged as a reproducible NixOS service image";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixos-generators }:
    let
      # The scanner and dev shell build anywhere. The NixOS image is Linux-only.
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      # Disk images can only be produced on Linux, but either architecture
      # works -- an Apple Silicon VM builds the aarch64 image natively.
      imageSystems = [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.elfharden;

          # vendorHash is null because the tool depends only on the Go
          # standard library.
          elfharden = pkgs.buildGoModule {
            pname = "elfharden";
            version = "0.1.0";
            src = ./.;
            vendorHash = null;
            meta = {
              description = "Scans ELF binaries for PIE, NX, stack canary and RELRO";
              mainProgram = "elfharden";
            };
          };
        }
        # Bootable qcow2 image, Linux builders only.
        // nixpkgs.lib.optionalAttrs (builtins.elem system imageSystems) {
          # qcow2 packing runs a QEMU VM, so this derivation requires /dev/kvm.
          # It builds on bare metal and on CI runners with nested virtualisation,
          # but not inside a VM on hardware that cannot nest (Apple M1/M2).
          image = nixos-generators.nixosGenerate {
            inherit system;
            format = "qcow";
            modules = [ self.nixosModules.default ./nixos/configuration.nix ];
          };

          # ISO images are assembled with xorriso rather than a VM, so this
          # builds anywhere -- including inside a non-nesting VM.
          iso = nixos-generators.nixosGenerate {
            inherit system;
            format = "install-iso";
            modules = [ self.nixosModules.default ./nixos/configuration.nix ];
          };

          # The system closure alone, no bootable artifact. Fastest check that
          # the module evaluates and every unit builds.
          toplevel = self.nixosConfigurations.${system}.config.system.build.toplevel;
        });

      nixosModules.default = import ./nixos/module.nix self;

      # Named per architecture so both can be built and inspected.
      nixosConfigurations = nixpkgs.lib.genAttrs imageSystems (system:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            self.nixosModules.default
            ./nixos/configuration.nix
            {
              # A bare nixosSystem has no format module, so nothing declares a
              # disk layout. These placeholders exist only so the configuration
              # evaluates on its own; the generator formats override them.
              fileSystems."/" = {
                device = "/dev/disk/by-label/nixos";
                fsType = "ext4";
              };
              boot.loader.grub.devices = [ "/dev/vda" ];
            }
          ];
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.gopls pkgs.qemu ];
          };
        });
    };
}
