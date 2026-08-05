---
title: Flooding Dropper npm Supply Chain Campaign
slug: 2026-08-flooding-dropper
description: An automated supply chain campaign targeting npm, deploying multi-stage loaders across 850+ malicious packages that utilize DNS TXT fallback for C2 and reflective payload execution.
date: "2026-08-05T21:25:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - npm
  - malware
  - persistence
  - evasion
  - remote-access
products:
  - npm registry
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: Sonatype Research Labs is tracking an active malicious package campaign, dubbed 'Flooding Dropper,' spreading on npm.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
    evidence: Establishing persistence through both a Registry Run key and a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Impair Defenses
    evidence: Patching Event Tracing for Windows and Antimalware Scan Interface functions to interfere with monitoring and scanning.
    confidence_band: high
references:
  - https://www.sonatype.com/blog/flooding-dropper-hits-npm-with-850-malicious-packages
---

Sonatype Research Labs is tracking a large-scale supply chain attack campaign, dubbed 'Flooding Dropper' (sonatype-2026-005660), which involves over 850 malicious packages published to the npm registry. The campaign utilizes automated infrastructure to generate disposable npm accounts and packages, often incorporating keywords like 'bigops' and 'bnpl' with recurring version patterns in the 35.x.y range.

The delivery mechanism involves a first-stage JavaScript loader embedded in the package that executes upon installation. This loader performs host OS and architecture profiling to retrieve platform-specific payloads. A critical aspect of this campaign is its resiliency; it employs multiple delivery channels, including randomized HTTPS download hosts and a DNS TXT record fallback, to ensure payload delivery even when specific infrastructure is blocked. Once executed, the second-stage binary employs sophisticated evasion techniques, including patching Event Tracing for Windows (ETW) and the Antimalware Scan Interface (AMSI), as well as utilizing reflective in-memory loading to execute encrypted secondary payloads.

## Attack Chain

1. The victim installs a malicious npm package (e.g., bigops-api) via npm install.
2. The package executes an embedded JavaScript loader upon installation or import.
3. The loader profiles the host and attempts to download a binary payload from randomized hardcoded remote hosts.
4. Upon failure of the primary HTTPS download, the loader queries DNS TXT records to reconstruct the binary payload.
5. The payload is written to a temporary directory and launched as a detached background process to evade parent process monitoring.
6. The second-stage loader performs environment checks for sandboxes or debuggers.
7. The loader patches AMSI and ETW processes in memory to disable security telemetry.
8. Persistence is established via Registry Run keys and scheduled tasks, followed by the reflective execution of an encrypted secondary payload.

## Impact

The campaign has impacted over 846 software components on the npm registry, posing a risk to developer workstations, CI/CD pipelines, and production infrastructure. Successful exploitation allows for persistent unauthorized code execution, potential exfiltration of developer credentials (npm, GitHub, cloud), and the deployment of arbitrary payloads within internal development environments.

## Recommendation

- Identify and remove any packages identified under sonatype-2026-005660 from all local caches, internal repositories, and lockfiles.
- Audit CI/CD runners and build agents for unexpected detached background processes originating from Node.js or npm.
- Review environment telemetry for DNS TXT queries or outbound connections to unknown or randomized remote hosts associated with package installation.
- Rotate all sensitive credentials (npm, GitHub, cloud, CI/CD tokens) once the environment has been remediated.
- Implement dependency monitoring tools to detect and block packages matching the identified naming patterns and versioning characteristics.
