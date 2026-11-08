---
brief_id: brief-2026-11-08-openemr-path-traversal
event_id: brief-2026-11-08-openemr-path-traversal
revision: 1
activity_at: "2026-11-08T15:29:19Z"
title: 'OpenEMR: Path traversal in RingCentral RCFaxClient (CVE-2026-124490)'
slug: 2026-11-openemr-path-traversal
description: OpenEMR versions prior to 8.3.0 are vulnerable to path traversal within the RingCentral RCFaxClient disposeDocument() method, enabling authenticated attackers to read arbitrary files or achieve remote code execution via file writes.
date: "2026-11-08T15:29:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenEMR before 8.3.0 contains a path traversal vulnerability in the RingCentral RCFaxClient disposeDocument() method
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can use ... action=setup with base64 content to write web-executable files for code execution.
    confidence_band: high
cves:
  - id: CVE-2026-124490
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124490
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to 8.3.0 or later to patch CVE-2026-124490
      owner: IT Operations
      due: 24h
      evidence: OpenEMR before 8.3.0 contains a path traversal vulnerability
  hunt_leads:
    - lead: Search for HTTP requests targeting the faxsms module with directory traversal sequences or attempts to trigger the setup action
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-stem, cs-uri-query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Path traversal vulnerability in the RingCentral RCFaxClient disposeDocument() method of oe-module-faxsms
  mitigation_plan:
    - priority: immediate
      action: Apply OpenEMR 8.3.0 update
      owner: IT Operations
      addresses: CVE-2026-124490
      evidence: OpenEMR before 8.3.0 contains a path traversal vulnerability
---

OpenEMR versions before 8.3.0 contain a path traversal vulnerability in the RingCentral RCFaxClient disposeDocument() method of the oe-module-faxsms component. An authenticated attacker can exploit the file_path parameter to read sensitive files, such as configuration files containing credentials or source code. Furthermore, an attacker can use the action=setup parameter with base64-encoded content to write web-executable files, leading to remote code execution.

## Impact
The vulnerability allows authenticated attackers to perform unauthorized file system reads and writes, resulting in potential exposure of sensitive data (credentials/source code) and full system compromise via remote code execution.

## Recommendation
- Upgrade OpenEMR to version 8.3.0 or later immediately to resolve the vulnerable disposeDocument() method.
- Audit web server access logs for requests directed at the oe-module-faxsms component containing path traversal patterns (e.g., ../, ..\).
- Review user access privileges for the OpenEMR instance to limit exposure to authenticated session exploitation.
