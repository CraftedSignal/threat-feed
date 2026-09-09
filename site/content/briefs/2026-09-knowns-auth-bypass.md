---
title: Authentication Bypass in knowns Management API
slug: 2026-09-knowns-auth-bypass
description: The knowns application before version 0.30.0 exposes an unauthenticated management API on all network interfaces, allowing attackers to provision unauthorized tunnels via the /api/tunnel/start endpoint.
date: "2026-09-08T01:37:49Z"
lastmod: "2026-09-09T14:59:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:knowns_project:knowns:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - npm
  - cve-2026-86775
products:
  - knowns (< 0.30.0)
  - knowns (<= 0.29.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The knowns application before version 0.30.0 serves the management API without authentication on all network interfaces by default.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: In the default deployment, where the Management API is unauthenticated and bound to all interfaces, a remote unauthenticated attacker can supply a traversal payload
    confidence_band: high
cves:
  - id: CVE-2026-86543
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86543
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86775
rules:
  - title: Detects CVE-2026-86543 Exploitation - Unauthorized Tunnel Initiation
    description: Detects exploitation of the knowns management API by monitoring for POST requests to the /api/tunnel/start endpoint
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-86775 Exploitation - Path Traversal in Document API
    description: Detects path traversal attempts targeting the /api/docs endpoint by checking for dot-dot-slash sequences in the URI or request query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade knowns to version 0.30.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies versions before 0.30.0 are vulnerable
    - action: Audit network perimeter for knowns management API exposure
      owner: SOC
      due: 24h
      evidence: Source states API is served on all network interfaces by default
  mitigation_plan:
    - priority: immediate
      action: Upgrade knowns to 0.30.0
      owner: IT Operations
      addresses: CVE-2026-86543
      evidence: NVD advisory
updates:
  - at: "2026-09-09T14:59:50Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-86775 Exploitation - Path Traversal in Document API'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86775
---

The knowns application, in versions prior to 0.30.0, contains a critical authentication bypass vulnerability in its management API component. By default, this API is configured to listen on all network interfaces without requiring any form of authentication or credentials upon fresh installation. This misconfiguration allows unauthenticated remote attackers to interact with sensitive administrative endpoints. Specifically, an attacker can access the /api/tunnel/start endpoint to provision a new, unauthorized public tunnel. This action can be used to republish the internal management API to a publicly accessible address, effectively bypassing internal network boundaries and enabling further unauthorized access or control over the host system. Given the default behavior of exposing the API on all interfaces, this threat is highly accessible to any actor capable of reaching the service over the network.

## Impact

Successful exploitation allows for the unauthorized creation of external tunnels, potentially exposing internal-only services or management interfaces to the public internet. This can lead to unauthorized configuration changes, complete takeover of the knowns application instance, and lateral movement within the network. This vulnerability carries a CVSS v3.1 base score of 9.8.

## Recommendation

- Upgrade the knowns application to version 0.30.0 or later immediately to enforce authentication requirements on the management API.
- Implement network access control lists (ACLs) to restrict access to the knowns management API port to trusted internal management subnets only.
- Review network logs for unexpected inbound HTTP requests to the /api/tunnel/start endpoint, which is a strong indicator of unauthorized tunnel provisioning.
