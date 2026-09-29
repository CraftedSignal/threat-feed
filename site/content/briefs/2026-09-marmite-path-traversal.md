---
title: Path Traversal in Marmite Development Server
slug: 2026-09-marmite-path-traversal
description: Marmite versions 0.4.2 and earlier contain a path traversal vulnerability in the --serve development server allowing unauthenticated attackers to read arbitrary files.
date: "2026-09-29T18:29:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:marmite:marmite:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
vendors:
  - Marmite
products:
  - Marmite (<= 0.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Marmite through 0.4.2 contains a path traversal vulnerability in the development server started by --serve that allows unauthenticated attackers to read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-102810
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102810
rules:
  - title: Detect CVE-2026-102810 Path Traversal Attempt
    description: Detects path traversal attempts against the Marmite development server by identifying percent-encoded traversal sequences in URI requests
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems running Marmite <= 0.4.2
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-102810 affects versions <= 0.4.2
    - action: Deploy Sigma detection rule for path traversal patterns
      owner: Detection Engineering
      due: 72h
      evidence: Rule targets the documented CVE-2026-102810 vulnerability
  mitigation_plan:
    - priority: immediate
      action: Bind --serve to 127.0.0.1 on affected servers
      owner: IT Operations
      addresses: CVE-2026-102810
      evidence: Limits impact by restricting server access to local interface
---

Marmite versions 0.4.2 and earlier contain a path traversal vulnerability within the development server component, activated when the application is executed with the --serve flag. The vulnerability resides in the handle_request function within src/server.rs. The application performs insufficient validation on requested file paths, specifically failing to properly handle or neutralize directory traversal sequences (such as ../) after undergoing percent-decoding. 

This flaw allows an unauthenticated remote attacker to construct malicious HTTP requests containing encoded traversal sequences. When processed, these requests enable the attacker to escape the designated web root and access arbitrary files on the host file system. The scope of accessible files is restricted only by the permissions of the user account running the Marmite process. Given the vulnerability exists within a development server implementation, it poses a significant risk to developers and build environments where such components might be exposed to internal networks or local interfaces.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive configuration files, source code, credentials, or other system data residing on the server. In typical development environments, this could lead to the exposure of environment variables or database connection strings, facilitating further compromise.

## Recommendation

Prioritize the identification and remediation of Marmite instances in development environments.

* Upgrade Marmite to a patched version beyond 0.4.2 once available.
* Audit development environments using Marmite for exposure to untrusted networks.
* Restrict access to the Marmite development server (started via --serve) to localhost only, using binding flags such as --host 127.0.0.1.
