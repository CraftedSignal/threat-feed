---
title: Insecure Deserialization in Uniong WebITR
slug: 2026-10-webitr-deserialization
description: Uniong WebITR contains an insecure deserialization vulnerability, CVE-2026-113404, allowing authenticated remote attackers to execute arbitrary code via malicious serialized data.
date: "2026-10-20T08:33:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:uniong:webitr:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - deserialization
vendors:
  - Uniong
products:
  - WebITR
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated remote attackers can use the hard-coded cryptographic key to craft and submit malicious serialized data.
    confidence_band: high
cves:
  - id: CVE-2026-113404
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113404
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Limit access to WebITR application to trusted network segments.
      owner: SOC
      due: 24h
      evidence: Vulnerability allows authenticated remote exploitation.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches for CVE-2026-113404 as they are released.
      owner: IT Operations
      addresses: CVE-2026-113404
      evidence: Vendor security advisory.
---

WebITR, developed by Uniong, is affected by an insecure deserialization vulnerability identified as CVE-2026-113404. This vulnerability arises because the application utilizes a hard-coded cryptographic key to handle serialized objects. An authenticated remote attacker can exploit this weakness by crafting custom serialized payloads signed with the hard-coded key. When submitted to the application, the server deserializes these objects, resulting in arbitrary code execution on the underlying host. This flaw is critical for defenders because it permits full system compromise from a standard authenticated user session, bypassing standard application-level access controls.

## Impact

Successful exploitation allows for remote code execution on the server hosting the WebITR application. This impact is significant as it grants the attacker the privileges of the service account running the application, which could lead to full system takeover, lateral movement, or data exfiltration. The threat is categorized with a CVSS v3.1 base score of 8.8.

## Recommendation

- Monitor application logs for anomalous serialized data inputs or unexpected process execution spawned by the WebITR service account.
- Implement strict ingress filtering for the WebITR application to limit authentication to trusted IP ranges.
- Apply security patches provided by Uniong as soon as they become available for CVE-2026-113404.
- Ensure the service account running the WebITR application follows the principle of least privilege to minimize the impact of successful code execution.
