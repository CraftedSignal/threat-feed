---
brief_id: brief-2026-11-02-cwp-auth-bypass
event_id: brief-2026-11-02-cwp-auth-bypass
revision: 1
activity_at: "2026-11-02T15:47:47Z"
title: 'Control Web Panel: Authentication bypass via execution after redirect (CVE-2026-73696)'
slug: 2026-11-cwp-auth-bypass
description: Control Web Panel versions prior to 1.12 contain an execution after redirect vulnerability in the user panel authentication flow that allows attackers with a valid username to bypass authentication and achieve unauthorized code execution.
date: "2026-11-02T15:47:47Z"
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
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:control-webpanel:control_web_panel:*:*:*:*:*:*:*:*
vendors:
  - Control Web Panel
products:
  - Control Web Panel (< 1.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers with nothing more than a valid hosting username can bypass authentication to reach user-panel module code paths, enabling a pre-authentication chain to root access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing PHP execution to continue and the module dispatcher include to run without authentication. Attackers with nothing more than a valid hosting username can bypass authentication to reach user-panel module code paths, enabling a pre-authentication chain to root access.
    confidence_band: high
cves:
  - id: CVE-2026-73696
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73696
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Control Web Panel to version 1.12 or higher
      owner: IT Operations
      due: 24h
      evidence: Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redirect vulnerability
  hunt_leads:
    - lead: Identify access attempts to user-panel modules from accounts that lack successful authentication headers or sessions
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: the module dispatcher include to run without authentication
  mitigation_plan:
    - priority: immediate
      action: Upgrade to CWP version 1.12
      owner: IT Operations
      addresses: CVE-2026-73696
      evidence: Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redirect vulnerability
---

Control Web Panel (CWP) versions before 1.12 are vulnerable to an execution after redirect flaw within the user panel authentication process. The unauthenticatedFlow() function in CWPUserIndex initiates a redirect to the login page via toLoginWithIntendedUri() but fails to call exit(), which allows the PHP script execution to proceed. This flaw permits an attacker with a valid hosting username to reach module code paths that should be restricted, potentially leading to unauthorized access and privilege escalation.

## Impact

Successful exploitation allows unauthenticated users with a valid hosting account to bypass security controls and interact with internal user-panel modules, which can facilitate a chain of exploitation leading to root-level compromise of the server.

## Recommendation

Update all Control Web Panel instances to version 1.12 or later immediately to address the vulnerable authentication logic.
