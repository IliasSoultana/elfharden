# Minimal system definition: just enough to boot and run the scanner.
{ modulesPath, ... }:

{
  imports = [ "${modulesPath}/profiles/minimal.nix" ];

  services.elfharden = {
    enable = true;
    paths = [ "/run/current-system/sw/bin" ];
    interval = "daily";
  };

  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
  };

  users.users.root.openssh.authorizedKeys.keys = [
    # TODO: add your public key here before building the image, otherwise
    # the machine boots with no way in.
  ];

  # Bootloader and root filesystem are supplied by the nixos-generators
  # format module (qcow, iso, ...). Defining them here conflicts with it.

  system.stateVersion = "25.05";
}
