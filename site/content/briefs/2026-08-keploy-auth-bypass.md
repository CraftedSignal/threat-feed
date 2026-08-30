---
title: Unauthenticated Access to Keploy Agent Control Plane
slug: 2026-08-keploy-auth-bypass
description: Keploy versions 3.1.0 through 3.6.25 contain a vulnerability where the agent control-plane HTTP server binds to all interfaces without authentication, enabling unauthorized access to TLS session keys and recording management endpoints.
date: "2026-08-30T15:11:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:keploy:keploy:3.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:keploy:keploy:3.6.25:*:*:*:*:*:*:*
vendors:
  - Keploy
products:
  - Keploy (3.1.0 - 3.6.25)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can access the /agent/pcap/keylog endpoint to retrieve NSS keylog lines and decrypt recorded TLS traffic
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Attackers can access the /agent/pcap/keylog endpoint to retrieve NSS keylog lines
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82641
rules:
  - title: Detect Unauthenticated Access to Keploy Agent Endpoints
    description: Detects unauthorized access attempts to sensitive Keploy agent endpoints including keylog retrieval and session management.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Keploy instances to version 3.6.26 or later
      owner: IT Operations
      due: 48h
      evidence: Source document identifies versions 3.1.0-3.6.25 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement network ACLs to block external access to Keploy control plane endpoints
      owner: Network Security
      addresses: CVE-2026-82641
---

Keploy versions 3.1.0 through 3.6.25 include an insecure configuration where the agent control-plane HTTP server binds to all network interfaces (0.0.0.0) without requiring authentication. This exposure allows remote, unauthenticated attackers to interact with sensitive API endpoints. By accessing the /agent/pcap/keylog endpoint, an attacker can retrieve NSS keylog lines, which are sufficient to decrypt intercepted TLS traffic. Additionally, the vulnerability allows unauthorized access to management endpoints, specifically /agent/stop and /agent/storemocks, which can be leveraged to disrupt, terminate, or manipulate data recording sessions. This poses a significant risk to development and testing environments where Keploy is used to capture application traffic. Defenders should ensure Keploy instances are not exposed to untrusted networks and update to a patched version immediately.

## Impact

Successful exploitation allows for the decryption of sensitive TLS traffic captured during session recording and the unauthorized control or corruption of testing data streams. This vulnerability impacts development, staging, and testing environments where Keploy is deployed, potentially compromising internal credentials, API keys, or proprietary data transmitted within the recorded sessions.

## Recommendation

- Upgrade Keploy to version 3.6.26 or later to enforce authentication on control-plane endpoints.
- Implement network-level access control (firewall or security groups) to restrict access to the Keploy agent control-plane port to authorized management hosts only.
- Audit existing recording sessions for signs of unauthorized manipulation or access to the /agent/pcap/keylog endpoint.
