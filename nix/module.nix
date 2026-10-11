{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.passkey-proxy;

  unitName = name: "passkey-proxy-${name}";

  instanceModule = {name, ...}: {
    options = {
      enable =
        lib.mkEnableOption "this passkey-proxy instance"
        // {
          default = true;
        };

      rpid = lib.mkOption {
        type = lib.types.str;
        example = "example.com";
        description = ''
          Relying party domain, without a scheme. Changing it invalidates existing
          passkeys. Use the same value for instances sharing a login.
        '';
      };

      origin = lib.mkOption {
        type = lib.types.str;
        example = "https://app.example.com";
        description = "Public browser origin, including the scheme.";
      };

      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:9090";
        description = "HTTP listen address. Keep behind an HTTPS-terminating proxy.";
      };

      forward = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "http://127.0.0.1:3000";
        description = ''
          URL of the app to proxy. If null, requests are acked with a 204 after
          successful auth.
        '';
      };

      cookieDomain = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "example.com";
        description = ''
          Cookie domain for sharing logins across subdomains. Requires
          {option}`services.passkey-proxy.sessionKeyFile`. All apps on this
          domain must be trusted.
        '';
      };

      enroll = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "alice";
        description = ''
          Account to enroll at `/auth/enroll`. Unset after enrollment.
        '';
      };

      stateDirectory = lib.mkOption {
        type = lib.types.str;
        default = "passkey-proxy";
        description = ''
          Directory under `/var/lib` holding `passkeys.json`. Instances using
          the same directory share accounts.
        '';
      };

      environment = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = {};
        description = "Extra service environment variables, overriding option-derived values.";
      };
    };
  };

  enabled = lib.filterAttrs (_: i: i.enable) cfg.instances;

  # Keep the signing key out of the Nix store. Identical for every instance,
  # so it is built once rather than per unit.
  withSessionKey = pkgs.writeShellScript "passkey-proxy" ''
    set -eu
    PASSKEY_SESSION_KEY="$(cat "$CREDENTIALS_DIRECTORY/session-key")"
    export PASSKEY_SESSION_KEY
    exec ${lib.getExe cfg.package}
  '';
in {
  options.services.passkey-proxy = {
    package = lib.mkOption {
      type = lib.types.package;
      # Not mkPackageOption: pkgs.passkey-proxy exists only once the flake's
      # overlay is applied, so the module would break without it.
      default = pkgs.callPackage ./package.nix {};
      defaultText = lib.literalExpression "pkgs.passkey-proxy";
      description = "The passkey-proxy package to use.";
    };

    sessionKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/passkey-session-key";
      description = ''
        Secret file containing the cookie signing key shared by all instances.
        Keep outside the Nix store. If unset, keys change on restart,
        invalidating sessions.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "passkey-proxy";
      description = "User running all instances.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "passkey-proxy";
      description = "Group running all instances.";
    };

    instances = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule instanceModule);
      default = {};
      description = "Proxy instances, each creating a `passkey-proxy-<name>.service` unit.";
      example = lib.literalExpression ''
        {
          grafana = {
            rpid = "example.com";
            origin = "https://grafana.example.com";
            listen = "127.0.0.1:9090";
            forward = "http://127.0.0.1:3000";
            cookieDomain = "example.com";
          };
        }
      '';
    };
  };

  config = lib.mkIf (enabled != {}) {
    assertions = [
      {
        assertion =
          (lib.filterAttrs (_: i: i.cookieDomain != null) enabled)
          == {}
          || cfg.sessionKeyFile != null;
        message = ''
          services.passkey-proxy: cookieDomain needs sessionKeyFile, since
          otherwise each instance signs cookies the others reject.
        '';
      }
    ];

    users.users = lib.mkIf (cfg.user == "passkey-proxy") {
      passkey-proxy = {
        isSystemUser = true;
        group = cfg.group;
      };
    };
    users.groups = lib.mkIf (cfg.group == "passkey-proxy") {passkey-proxy = {};};

    systemd.services =
      lib.mapAttrs' (
        name: i:
          lib.nameValuePair (unitName name) {
            description = "passkey-proxy (${name})";
            wantedBy = ["multi-user.target"];
            after = ["network.target"];

            environment =
              {
                PASSKEY_RPID = i.rpid;
                PASSKEY_ORIGIN = i.origin;
                PASSKEY_LISTEN = i.listen;
                PASSKEY_FILE = "/var/lib/${i.stateDirectory}/passkeys.json";
              }
              // lib.optionalAttrs (i.forward != null) {PASSKEY_FORWARD = i.forward;}
              // lib.optionalAttrs (i.cookieDomain != null) {
                PASSKEY_COOKIE_DOMAIN = i.cookieDomain;
              }
              // lib.optionalAttrs (i.enroll != null) {PASSKEY_ENROLL = i.enroll;}
              // i.environment;

            serviceConfig = {
              ExecStart =
                if cfg.sessionKeyFile == null
                then lib.getExe cfg.package
                else withSessionKey;
              LoadCredential = lib.optional (
                cfg.sessionKeyFile != null
              ) "session-key:${cfg.sessionKeyFile}";

              User = cfg.user;
              Group = cfg.group;
              StateDirectory = i.stateDirectory;
              StateDirectoryMode = "0750";
              Restart = "on-failure";
              RestartSec = "5s";

              # The proxy only needs to talk TCP and write its passkey file.
              CapabilityBoundingSet = [];
              LockPersonality = true;
              MemoryDenyWriteExecute = true;
              NoNewPrivileges = true;
              PrivateDevices = true;
              PrivateTmp = true;
              ProtectClock = true;
              ProtectControlGroups = true;
              ProtectHome = true;
              ProtectHostname = true;
              ProtectKernelLogs = true;
              ProtectKernelModules = true;
              ProtectKernelTunables = true;
              ProtectProc = "invisible";
              ProtectSystem = "strict";
              RestrictAddressFamilies = [
                "AF_INET"
                "AF_INET6"
                "AF_UNIX"
              ];
              RestrictNamespaces = true;
              RestrictRealtime = true;
              RestrictSUIDSGID = true;
              SystemCallArchitectures = "native";
              SystemCallFilter = [
                "@system-service"
                "~@privileged"
                "~@resources"
              ];
              UMask = "0077";
            };
          }
      )
      enabled;
  };
}
