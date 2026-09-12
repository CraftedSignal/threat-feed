---
title: Unconditional SSH Host-Key Trust in Central Dogma Git Mirror
slug: 2026-09-ssh-host-key-bypass
description: Central Dogma's Git mirror SSH client disables host-key verification, allowing on-path attackers to perform Man-in-the-Middle (MitM) attacks to exfiltrate sensitive configuration data or inject malicious commits.
date: "2026-09-12T00:58:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:linecorp:centraldogma:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - git
  - ssh
  - mitm
  - cve-2026-11745
vendors:
  - LINE Corporation
products:
  - centraldogma-server-mirror-git (< 0.84.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: An on-path attacker on the corporate network... ARP spoofing on the LAN, internal DNS poisoning, malicious internal DNS overriding github.com.
    confidence_band: high
cves:
  - id: CVE-2026-11745
    epss: 0.00219
references:
  - https://github.com/advisories/GHSA-vjfw-cpmh-xwv3
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade centraldogma-server-mirror-git to version 0.84.0
      owner: IT Operations
      due: 24h
      evidence: Source provides fixed version 0.84.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v0.84.0
      owner: IT Operations
      addresses: CVE-2026-11745
      evidence: Source advises upgrading to version 0.84.0.
---

Central Dogma (vulnerable version < 0.84.0) contains a critical security defect in its Git mirroring component, specifically within `SshGitMirror.java`. The application utilizes an Apache MINA SSHD `ServerKeyVerifier` implementation that unconditionally returns `true` for all outbound SSH connections. This effectively disables SSH host-key verification for `git+ssh://` mirrors. 

The application provides no mechanism for operators to enable host-key pinning or known-hosts verification. Consequently, the client blindly trusts any host key presented by a remote server during the initial handshake. This vulnerability, tracked as CVE-2026-11745, allows an on-path attacker to position themselves between the Central Dogma server and its upstream Git repository. Because Central Dogma is frequently used to store sensitive configurations, including database credentials and third-party API keys, successful exploitation leads to the complete compromise of the configuration store and subsequent supply-chain propagation to all dependent microservices.

## Attack Chain

1. Attacker achieves on-path network position via ARP spoofing, internal DNS poisoning, or BGP hijacking.
2. Central Dogma initiates an outbound `git+ssh` connection to a configured upstream repository.
3. The attacker intercepts the connection request and responds as a malicious SSH server.
4. The victim's `SshGitMirror` client receives the attacker's ephemeral RSA host key and, due to the hardcoded `true` return value in the verifier, accepts the host key without validation.
5. The attacker completes the SSH handshake and proceeds to request authentication.
6. The attacker captures the client's credentials or public key fingerprints offered during the authentication phase.
7. If exfiltrating, the attacker serves the contents of the mirrored repository to the client for inspection/storage.
8. If injecting, the attacker provides arbitrary commits, which Central Dogma then propagates to all downstream services consuming the compromised configuration.

## Impact

The vulnerability poses a severe risk to organizational secrets, as Central Dogma is primarily used as a configuration management store. An attacker can intercept database credentials, certificates, and feature flags. Furthermore, because Central Dogma pushes updates to subscribing microservices, an attacker can push malicious configurations, causing a broad supply-chain compromise across the organization. The vulnerability has been confirmed reproducible via a `paramiko`-based fake SSH server.

## Recommendation

1. Upgrade `com.linecorp.centraldogma:centraldogma-server-mirror-git` to version 0.84.0 or later to mitigate CVE-2026-11745.
2. Audit existing Git mirror configurations to identify if attackers could have already intercepted traffic, given the lack of historical host-key verification.
3. Implement host-key fingerprinting for all internal Git repositories to support the new pinning functionality introduced in the patched version.
