{
  lib,
  buildGo127Module,
}:
buildGo127Module {
  pname = "passkey-proxy";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    # Only what the build reads, so editing the README does not rebuild.
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../main.go
      ../server.go
      ../web
      ../internal
    ];
  };

  # Use lib.fakeHash to obtain a new hash when dependencies change.
  vendorHash = "sha256-TXMdaTg40N2cXkTeQRg6TjFxJ5nvtjRKDiSg1VDV1Uo=";

  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
  ];

  meta = {
    description = "Reverse proxy that puts a backend server behind a passkey login";
    homepage = "https://github.com/tommyknows/passkey-proxy";
    mainProgram = "passkey-proxy";
    platforms = lib.platforms.unix;
  };
}
