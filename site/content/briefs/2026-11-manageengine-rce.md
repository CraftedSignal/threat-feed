---
brief_id: brief-2026-11-02-manageengine-rce
event_id: brief-2026-11-02-manageengine-rce
revision: 1
activity_at: "2026-11-02T11:29:01Z"
title: 'Zohocorp ManageEngine Eventlog Analyzer and Log360: Authenticated remote code execution (CVE-2026-8923)'
slug: 2026-11-manageengine-rce
description: ManageEngine Eventlog Analyzer and Log360 versions prior to 13062 contain an authenticated remote code execution vulnerability in the log forwarding feature.
date: "2026-11-02T11:29:01Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:zohocorp:manageengine_eventlog_analyzer:*:*:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_log360:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - enterprise-software
vendors:
  - Zohocorp
products:
  - ManageEngine Eventlog Analyzer (< 13062)
  - ManageEngine Log360 (< 13062)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: ManageEngine Eventlog Analyzer and Log360 versions prior to 13062 contain an authenticated remote code execution vulnerability within the log forwarding feature.
    confidence_band: high
cves:
  - id: CVE-2026-8923
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8923
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ManageEngine Eventlog Analyzer and Log360 to 13062 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requires version update
  hunt_leads:
    - lead: Identify unusual process creation initiated by ManageEngine service accounts
      technique_id: T1059
      data_needed:
        - Process creation logs (EID 1 / Audit Process Creation)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: RCE vulnerability implies arbitrary command execution
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 13062
      owner: IT Operations
      addresses: CVE-2026-8923
      evidence: Vendor patch version
---

Zohocorp ManageEngine Eventlog Analyzer and ManageEngine Log360 versions before 13062 are vulnerable to authenticated remote code execution (RCE) via the Log Forwarding configuration option. An attacker with valid credentials can leverage this feature to execute arbitrary code on the underlying host system.

## Impact
Successful exploitation allows an authenticated user to achieve remote code execution on the server hosting the ManageEngine application, potentially leading to full system compromise.

## Recommendation
- Upgrade ManageEngine Eventlog Analyzer and ManageEngine Log360 to version 13062 or later immediately.
- Audit existing ManageEngine administrative accounts and restrict access to the Log Forwarding configuration interface to verified administrators only.
- Review historical logs for any unusual modifications to log forwarding settings or suspicious process execution spawning from the ManageEngine service account.
