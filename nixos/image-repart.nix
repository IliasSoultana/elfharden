# A reproducible, integrity-protected disk image.
#
# This follows the approach Edgeless Systems use for Contrast's pod-VM images
# (packages/nixos/image.nix): build with systemd-repart rather than a QEMU VM,
# store the root filesystem as read-only erofs, and protect it with dm-verity.
#
# Two properties matter and they are linked:
#
#   * Integrity. The verity partition holds a Merkle tree over the root
#     filesystem, so the root hash fixes every byte of the image. Tampering
#     with any block is detectable at read time.
#
#   * Reproducibility. The same inputs must produce the same bytes, otherwise
#     the root hash is meaningless as an identity. That is why partition UUIDs
#     are pinned and hardlinks are dereferenced below.
#
# Together these are what makes a measurement worth attesting: the hash
# identifies the image, and anyone can rebuild from source and get that hash.
#
# Unlike the qcow2 target, this needs no KVM, because systemd-repart assembles
# the image directly instead of booting a VM to do it.
{ config, lib, modulesPath, ... }:

{
  imports = [ "${modulesPath}/image/repart.nix" ];

  system.image.version = "1";

  # Nothing here boots via a bootloader; the image is meant to be measured
  # and mounted, so the loader assertions are switched off.
  boot.loader.grub.enable = false;
  fileSystems."/" = {
    device = "/dev/disk/by-label/root";
    fsType = "erofs";
  };

  documentation = {
    man.enable = false;
    nixos.enable = false;
  };

  image.repart = {
    name = "elfharden";
    inherit (config.system.image) version;

    mkfsOptions.erofs = [
      # Without this, a store with hardlink optimisation enabled produces a
      # different inode count, and therefore a different image, than one
      # without it. Same sources, different hash: reproducibility broken.
      "--hard-dereference"
    ];

    partitions = {
      "10-root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "erofs";
          Label = "root";
          Verity = "data";
          VerityMatchKey = "root";
          Minimize = "best";
          MakeDirectories = "/bin /boot /dev /etc /home /nix /proc /root /run /sys /tmp /usr/bin /var";
          UUID = "null"; # Pinned so the image is byte-identical across builds.
        };
      };

      # The Merkle tree over the partition above. Its root hash is the
      # image's identity.
      "20-root-verity" = {
        repartConfig = {
          Type = "root-verity";
          Label = "root-verity";
          Verity = "hash";
          VerityMatchKey = "root";
          Minimize = "best";
          UUID = "null";
        };
      };
    };
  };
}
