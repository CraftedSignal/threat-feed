---
brief_id: brief-2026-10-28-pie-register-rce
event_id: brief-2026-10-28-pie-register-rce
revision: 1
activity_at: "2026-10-28T04:19:11Z"
title: 'Pie Register Premium: Unrestricted file upload remote code execution (CVE-2026-84999)'
slug: 2026-10-pie-register-rce
description: The Pie Register Premium WordPress plugin contains an unrestricted file upload vulnerability in the piereg_file_upload function that allows unauthenticated attackers to achieve remote code execution.
date: "2026-10-28T04:19:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:pieregister:pie_register_premium:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - remote-code-execution
  - web-application-vulnerability
vendors:
  - Pie Register
products:
  - Pie Register Premium (<= 3.8.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files of dangerous types (e.g. PHP scripts) that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: The server returns the generated destination filename in the response, giving the attacker the exact path needed to trigger the uploaded file.
    confidence_band: high
cves:
  - id: CVE-2026-84999
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84999
rules:
  - title: Detects CVE-2026-84999 Exploitation - Unauthenticated File Upload via piereg_file_upload
    description: Detects exploitation of CVE-2026-84999 by monitoring for HTTP requests to the Pie Register upload AJAX action containing potential file extensions for code execution.
    platform: sigma
    severity: critical
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Pie Register Premium to a version greater than 3.8.4.0
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to, and including, 3.8.4.0
  hunt_leads:
    - lead: Identify suspicious file uploads to the WordPress content directory
      technique_id: T1505.003
      data_needed:
        - File creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The server returns the generated destination filename in the response
  mitigation_plan:
    - priority: immediate
      action: Upgrade Pie Register Premium to patched version
      owner: IT Operations
      addresses: CVE-2026-84999
      evidence: Plugin vulnerable in all versions up to, and including, 3.8.4.0
---

Pie Register Premium for WordPress, in all versions up to and including 3.8.4.0, contains an unrestricted file upload vulnerability (CVE-2026-84999). The piereg_file_upload function performs file type validation calls using wp_check_filetype and wp_check_filetype_and_ext but fails to verify the return status of these functions before calling move_uploaded_file. Furthermore, the AJAX handler lacks both nonce verification and capability checks, enabling unauthenticated remote code execution. Successful exploitation results in the server returning the full path to the uploaded file, allowing immediate remote execution.

## Impact

Successful exploitation allows an unauthenticated attacker to upload and execute arbitrary scripts, such as PHP backdoors, on the host web server.

## Recommendation

- Update Pie Register Premium to a version later than 3.8.4.0 immediately.
- Implement the detection rule below to identify exploitation attempts targeting the file upload endpoint.
- Audit the uploads directory for unexpected PHP or other executable files.
