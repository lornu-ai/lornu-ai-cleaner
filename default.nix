{ pkgs, rustBuilder, ociBuilder, craneLib, craneLibNightly, agentSrc, sharedSrc }:

let
  agentName = "ai-agent-cleaner";
  agentDescription = "AI agent for automated resource cleanup and housekeeping";
  agentCapabilities = [
    "resource_cleanup"
    "housekeeping"
  ];

  agent = rustBuilder.buildRustAgent {
    name = agentName;
    src = agentSrc;
    sharedSrc = sharedSrc;
    useNightly = false;
    cargoExtraArgs = "";
    buildInputs = [];
    nativeBuildInputs = [];
  };

  container = ociBuilder.buildMinimalImage {
    name = agentName;
    binary = agent.package;
    description = agentDescription;
    capabilities = agentCapabilities;
    tag = "latest";
    port = 8080;
    extraEnv = [];
  };

in {
  package = agent.package;
  inherit container;
  clippy = agent.clippy;
  tests = agent.tests;
  fmt = agent.fmt;
  doc = agent.doc;
  inherit (agent) cargoArtifacts;
}
