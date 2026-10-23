---
brief_id: brief-2026-10-23-coraza-waf-bypass
event_id: brief-2026-10-23-coraza-waf-bypass
revision: 1
activity_at: "2026-10-23T01:19:09Z"
title: 'Coraza WAF: Multipart upload filename parsing bypass (CVE-2026-114101)'
slug: 2026-10-coraza-waf-bypass
description: Coraza WAF versions prior to 3.8.1 contain a filename parsing vulnerability that allows attackers to bypass file-based security rules using specifically crafted multipart upload parameters.
date: "2026-10-23T01:19:09Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:coraza:coraza_waf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - waf
  - web-application
  - bypass
vendors:
  - Coraza
products:
  - Coraza WAF (< 3.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Coraza WAF multipart upload filename parsing allows bypassing FILES-based WAF rules.
    confidence_band: high
cves:
  - id: CVE-2026-114101
    cvss: 4
    epss: 0.00198
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=61FF52EA-AE7E-516E-80F6-E36419433611
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-114101
  - https://sploitus.com/exploit?id=61FF52EA-AE7E-516E-80F6-E36419433611&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Coraza WAF to version 3.8.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 3.8.1 as the required fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Coraza WAF to 3.8.1 or later
      owner: IT Operations
      addresses: CVE-2026-114101
      evidence: Vendor recommendation for version update.
---

Coraza WAF versions before 3.8.1 contain a vulnerability (CVE-2026-114101) in the multipart upload filename parsing logic. The underlying use of Go's `mime.ParseMediaType` function causes the parser to ignore RFC 5987 `filename*` parameters that utilize non-UTF-8 or non-US-ASCII character sets. An attacker can leverage this behavior by providing a decoy filename parameter while utilizing an unsupported character set encoding (e.g., `iso-8859-1`) to bypass security rules configured to inspect file types or names, allowing malicious files to reach the backend application.

## Impact

Successful exploitation allows for the bypass of WAF file-based security rules. This enables an attacker to upload potentially malicious files that would otherwise be blocked by the WAF, increasing the risk of remote code execution or unauthorized file access on the backend application.

## Recommendation

- Upgrade Coraza to version 3.8.1 or later by updating the dependency in `go.mod`.
- Audit existing WAF rules that rely on `FILES` or filename-based inspection to determine if they are susceptible to bypasses using non-standard character set encodings.
- Implement additional file validation logic on the backend application server as a secondary defense layer, independent of WAF inspection.
