---
brief_id: brief-2026-11-08-openemr-path-traversal-803ffbda
event_id: brief-2026-11-08-openemr-path-traversal-803ffbda
revision: 1
activity_at: "2026-11-08T16:50:56Z"
title: 'OpenEMR: Arbitrary file read and write vulnerability (CVE-2026-124450)'
slug: 2026-11-openemr-path-traversal-803ffbda
description: OpenEMR versions prior to 8.3.0 are vulnerable to path traversal in the fax/sms module, allowing authenticated attackers to read sensitive files and execute arbitrary code via file write.
date: "2026-11-08T16:50:56Z"
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
  - cpe:2.3:a:openemr:openemr:*:*:*:*:*:*:*:*
tags:
  - cve-2026-124450
  - path-traversal
  - rce
  - webserver
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated low-privilege users can read sqlconf.php to recover database credentials and write arbitrary files as the web user, enabling remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-124450
    cvss: 9.9
    kev_status: "false"
references:
  - https://github.com/openemr/openemr/security/advisories/GHSA-wf4w-mx2w-j4vv
  - https://www.vulncheck.com/advisories/openemr-before-8.3.0-arbitrary-file-read-write-via-disposedocument
  - https://sploitus.com/exploit?id=CVE-2026-124450&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to 8.3.0 or later
      owner: IT Operations
      due: 24h
      evidence: OpenEMR before 8.3.0 contains a broken access control and path traversal vulnerability
  hunt_leads:
    - lead: Hunt for web requests targeting the fax/sms module containing path traversal sequences (e.g., ../)
      technique_id: T1210
      data_needed:
        - Web server access logs (URI, method, parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Path traversal vulnerability in the fax/sms module disposeDocument action via an unvalidated file_path parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124450
      evidence: OpenEMR before 8.3.0 contains a broken access control and path traversal vulnerability
---

OpenEMR versions prior to 8.3.0 contain a broken access control and path traversal vulnerability in the fax/sms module's 'disposeDocument' action. The vulnerability stems from an unvalidated 'file_path' parameter, which allows authenticated, low-privileged users to perform arbitrary file reads (including the retrieval of database credentials from 'sqlconf.php') and arbitrary file writes as the web service user, ultimately leading to remote code execution.

## Impact

Authenticated low-privilege users can recover database credentials, modify application configuration, or achieve remote code execution on the underlying server as the web service user.

## Recommendation

* Patch OpenEMR to version 8.3.0 or later immediately to resolve the vulnerability.
* Audit access logs for authentication-related activity followed by suspicious requests to the 'fax/sms' module.
* Monitor for unauthorized file modification in the OpenEMR web directory.
