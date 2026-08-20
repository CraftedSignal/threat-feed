---
title: Supply Chain Attack Targeting Rust Ecosystem via Malicious Crate Dependencies
slug: 2026-08-rust-supply-chain
description: Threat actors associated with DPRK campaigns compromised the Rust crates.io registry by injecting malicious build scripts into typosquatted dependencies to execute a backdoor on developer and build environments.
date: "2026-08-20T19:09:48Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - arrayref (0.3.10)
  - internment (0.8.7)
  - append-only-vec (0.1.9)
  - proc-macro1
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: The malicious crates added a typosquatted dependency (proc-macro1) whose build script downloads and executes a remote binary.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: "Writes it to /tmp/rust-setup (Unix) or %TEMP%\rust-setup.ps1 (Windows) and executes the payload."
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Persists via Registry Run key (Windows), LaunchAgent (macOS), or systemd user service (Linux).
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1560.001
    technique_name: 'Archive Collected Data: Archive via Utility'
    evidence: Steals browser credentials from Chrome, Brave, and Edge by querying SQLite login databases.
    confidence_band: high
references:
  - https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
iocs:
  - type: ip
    value: 23.254.165.112
  - type: ip
    value: 23.254.167.107
  - type: domain
    value: hwsrv-798836.hostwindsdns.com
  - type: hash_sha256
    value: 25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae
  - type: hash_sha256
    value: 61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4
ioc_counts:
  domain: 1
  hash_sha256: 2
  ip: 2
---

On August 20, 2026, researchers identified a sophisticated supply chain attack targeting the Rust ecosystem. Attackers compromised maintainer credentials to publish malicious versions of three widely used crates: arrayref (0.3.10), internment (0.8.7), and append-only-vec (0.1.9). These crates were modified to include a dependency on 'proc-macro1', a typosquatted version of the legitimate 'proc-macro2' crate.

The attack leverages the fact that Cargo build scripts are executed with user privileges at compile time. By embedding malicious logic within the build.rs file of the typosquatted crate, the attackers achieve remote code execution whenever an affected project is built. The second-stage payload is a feature-rich backdoor capable of host reconnaissance, browser credential theft, and persistent access. Infrastructure analysis reveals significant overlap with prior supply chain campaigns attributed to North Korean state-sponsored actors, specifically the Mastra and axios campaigns, utilizing Hostwinds LLC infrastructure. Given the ubiquity of these crates, any workstation or CI/CD runner that has built an affected version should be treated as compromised.

## Attack Chain

1. Attacker compromises crates.io maintainer credentials or workstation to gain publication access.
2. Attacker publishes malicious versions of arrayref, internment, and append-only-vec, injecting a dependency on the typosquatted 'proc-macro1' crate.
3. Victim project builds a dependency tree including the malicious 'proc-macro1' crate.
4. Cargo triggers the malicious 'build.rs' script within 'proc-macro1' during the compilation phase.
5. Build script reconstructs the C2 URL from Base64 fragments and downloads a platform-specific binary payload (e.g., Linux, Windows, or macOS).
6. The payload is written to a temporary directory (/tmp/rust-setup or %TEMP%\rust-setup.ps1) and executed in the background.
7. The backdoor establishes persistence via systemd services, Registry Run keys, or LaunchAgents.
8. The backdoor exfiltrates host metadata and stolen browser credentials to the C2 server using HTTPS POST requests.

## Impact

The campaign affects any developer workstation or automated CI/CD environment that compiled the compromised crates. Successful execution results in full system access, persistent backdoor deployment, and the exfiltration of credentials stored in Chrome, Brave, and Edge browsers. As arrayref is present in a significant percentage of Rust environments, the potential exposure for enterprise build pipelines is substantial, necessitating a full credential rotation and forensic review of affected infrastructure.

## Recommendation

1. Perform an immediate search for the compromised crate versions (arrayref 0.3.10, internment 0.8.7, append-only-vec 0.1.9) in all 'Cargo.lock' files and local registry caches.
2. Treat all hosts that have compiled these crates as compromised; rotate all credentials, signing keys, and CI secrets accessible from those machines.
3. Delete malicious artifacts including '/tmp/rust-setup', '%TEMP%\rust-setup.ps1', and '%TEMP%\rust-setup-launch.vbs'.
4. Block the C2 IP addresses (23.254.165.112 and 23.254.167.107) and the domain 'hwsrv-798836.hostwindsdns.com' at the network perimeter.
5. Review all new or modified 'build-dependencies' entries in 'Cargo.toml' files, specifically flagging crates that perform unexpected network activity.
