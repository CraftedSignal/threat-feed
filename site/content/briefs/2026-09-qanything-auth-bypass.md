---
title: Authentication Bypass in QAnything 2.0.0
slug: 2026-09-qanything-auth-bypass
description: QAnything 2.0.0 contains an authentication bypass vulnerability in multiple API endpoints that allows unauthenticated attackers to exfiltrate sensitive uploaded documents and knowledge base files.
date: "2026-09-04T15:30:50Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:qanything:qanything:2.0.0:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-85671
vendors:
  - QAnything
products:
  - QAnything (2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: QAnything 2.0.0 contains an authentication bypass vulnerability... that allows unauthenticated attackers to access any uploaded file.
    confidence_band: high
cves:
  - id: CVE-2026-85671
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85671
rules:
  - title: Detects CVE-2026-85671 Exploitation - Unauthorized Access to QAnything Document Endpoints
    description: Detects unauthenticated access attempts to QAnything document retrieval endpoints that may indicate exploitation of CVE-2026-85671
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for access to /api/local_doc_qa/ endpoints
      owner: SOC
      due: 24h
      evidence: Source document identifies these endpoints as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade QAnything to a patched version or restrict network access to the API
      owner: IT Operations
      addresses: CVE-2026-85671
      evidence: NVD vulnerability disclosure
---

QAnything version 2.0.0 is affected by an authentication bypass vulnerability within its local document question-answering service. Specifically, the endpoints /api/local_doc_qa/get_file_base64 and /api/local_doc_qa/get_doc lack proper authorization checks, enabling unauthenticated remote attackers to retrieve stored files. By identifying and manipulating file identifiers in requests to these endpoints, an attacker can obtain base64-encoded file contents or parsed document chunks. This flaw allows unauthorized access to cross-tenant knowledge base content, potentially leading to the leakage of intellectual property or sensitive business data uploaded to the QAnything platform. There is no evidence in the source that this is currently being exploited in the wild, but the vulnerability is high-severity due to the ease of access to stored documents.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate any document or file indexed by the QAnything 2.0.0 knowledge base, resulting in a total compromise of the confidentiality of the data stored within the platform.

## Recommendation

- Patch QAnything to the latest version immediately or restrict network access to the /api/local_doc_qa/ endpoints until a vendor-supplied update is applied.
- Review web server access logs for repeated HTTP GET requests to the identified vulnerable endpoints originating from unexpected or unauthorized IP addresses.
- Deploy WAF rules to intercept and block unauthenticated traffic directed at the specific /api/local_doc_qa/ paths identified in this brief.
