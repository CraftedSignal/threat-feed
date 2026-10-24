---
brief_id: brief-2026-10-24-telerik-rce-chain
event_id: brief-2026-10-24-telerik-rce-chain
revision: 1
activity_at: "2026-10-24T11:13:13Z"
title: 'Progress Telerik Report Server: Pre-authentication Remote Code Execution (CVE-2024-4358 and CVE-2024-1800)'
slug: 2026-10-telerik-rce-chain
description: Progress Telerik Report Server is vulnerable to a pre-authentication remote code execution chain involving authentication bypass (CVE-2024-1800) and insecure deserialization (CVE-2024-4358) via the report management API.
date: "2026-10-24T11:13:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:telerik:report_server_2024:*:*:*:*:*:*:*:*
  - cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*
tags:
  - telerik
  - rce
  - deserialization
  - cve-2024-4358
  - cve-2024-1800
vendors:
  - Progress
products:
  - Telerik Report Server (< 10.0.24.130)
  - Telerik Report Server (<= 10.0.24.305)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Telerik Report Server pre-auth RCE via authentication bypass and deserialization exploit chain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: RCE via insecure deserialization in report processing when uploading a malicious .trdp payload
    confidence_band: high
cves:
  - id: CVE-2024-1800
    cvss: 9.9
    epss: 0.34247
    kev_status: "false"
  - id: CVE-2024-4358
    cvss: 9.8
    epss: 0.97482
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HARYDHK7-CVE-2024-4358
  - https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HARYDHK7-CVE-2024-4358&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2024-4358 Exploitation - Malicious API POST Request
    description: Detects exploitation attempts against the Telerik Report Server API by identifying POST requests to the report upload endpoint that likely involve the deserialization chain.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Telerik Report Server to version 10.0.24.130 or higher
      owner: IT Operations
      due: 24h
      evidence: 'Vendor mitigation recommendation: https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358'
    - action: Hunt for anomalous account creation events on Telerik Report Server
      owner: SOC
      due: 24h
      evidence: Exploit chain involves creating a backdoor account
  hunt_leads:
    - lead: Identify suspicious new user accounts created in the Telerik Report Server application audit logs
      technique_id: T1133
      data_needed:
        - Telerik Report Server Application Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit code automates the creation of a backdoor username and password.
---

Progress Telerik Report Server contains an authentication bypass vulnerability (CVE-2024-1800) that, when chained with an insecure deserialization vulnerability (CVE-2024-4358), allows unauthenticated attackers to achieve remote code execution. Exploitation involves bypassing authentication to create a backdoor account and subsequently uploading a malicious .trdp report file to the '/api/reportserver/report' endpoint, which triggers deserialization of the malicious payload. Publicly available exploit code confirms the feasibility of this attack chain.

## Attack Chain

1. Attacker sends a request to the target to initiate the authentication bypass (CVE-2024-1800).
2. Attacker creates a new administrative or backdoor user account on the Telerik Report Server.
3. Attacker authenticates as the newly created backdoor user to obtain an access token.
4. Attacker uses the authenticated session to target the '/api/reportserver/report' endpoint.
5. Attacker uploads a malicious '.trdp' report file containing a serialized payload.
6. The server deserializes the payload, resulting in arbitrary code execution on the underlying host.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full system access, enabling the execution of arbitrary commands, data exfiltration, or deployment of further payloads.

## Recommendation

- Upgrade Progress Telerik Report Server to version 10.0.24.130 or higher immediately as specified in the Progress knowledge base.
- Monitor logs for unauthorized account creation events on Telerik Report Server instances.
- Inspect HTTP traffic to the '/api/reportserver/report' endpoint for anomalous POST requests containing serialized object patterns or suspicious filenames.
