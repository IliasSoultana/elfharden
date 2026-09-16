# NixOS module exposing elfharden as a periodically-run, sandboxed service.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.elfharden;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.elfharden;
in
{
  options.services.elfharden = {
    enable = lib.mkEnableOption "the ELF hardening scanner";

    paths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "/run/current-system/sw/bin" ];
      description = "Directories or files to scan.";
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "systemd OnCalendar expression controlling scan frequency.";
    };

    reportPath = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/elfharden/report.json";
      description = "Where the JSON report is written.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkg ];

    systemd.services.elfharden = {
      description = "ELF hardening scan";

      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "elfharden-scan" ''
          ${lib.getExe pkg} -json ${lib.escapeShellArgs cfg.paths} \
            > ${lib.escapeShellArg cfg.reportPath}
        '';

        # The scanner only ever reads binaries and writes one report, so the
        # unit is confined to exactly that.
        DynamicUser = true;
        StateDirectory = "elfharden";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        ReadWritePaths = [ (builtins.dirOf cfg.reportPath) ];
      };
    };

    systemd.timers.elfharden = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.interval;
        Persistent = true;
      };
    };
  };
}
