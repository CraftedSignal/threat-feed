---
brief_id: brief-2026-10-28-sunhillo-sureline-auth-bypass
event_id: brief-2026-10-28-sunhillo-sureline-auth-bypass
revision: 1
activity_at: "2026-10-28T00:13:52Z"
title: 'Sunhillo SureLine: Authentication bypass and remote code execution (CVE-2026-112352)'
slug: 2026-10-sunhillo-sureline-auth-bypass
description: Sunhillo SureLine versions before 9.1.5 allow unauthenticated attackers to forge session cookies for arbitrary user impersonation and root-level command execution.
date: "2026-10-28T00:13:52Z"
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
  validation_status: Needs environment validation of webserver logs
cpes:
  - cpe:2.3:a:sunhillo:sureline:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - remote-code-execution
  - network-appliance
vendors:
  - Sunhillo
products:
  - SureLine (< 9.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592.002
    technique_name: Software
    evidence: Attackers can guess default account names such as Admin or sftp_user and submit a forged username cookie to satisfy the login check
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: chaining into root command execution.
    confidence_band: high
cves:
  - id: CVE-2026-112352
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112352
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Sunhillo SureLine to version 9.1.5 or later
      owner: IT Operations
      due: 24h
      evidence: Sunhillo SureLine before 9.1.5 contains an authentication bypass vulnerability
  hunt_leads:
    - lead: Identify incoming web requests to networkDiag.cgi containing unusual or unexpected session cookie values
      technique_id: T1592.002
      data_needed:
        - Web server access logs
        - HTTP request headers
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated remote attacker to impersonate any user ... by forging a session cookie
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 9.1.5 or later
      owner: IT Operations
      addresses: CVE-2026-112352
      evidence: Sunhillo SureLine before 9.1.5 contains an authentication bypass vulnerability
---

Sunhillo SureLine versions prior to 9.1.5 contain an authentication bypass vulnerability. The application utilizes a weak session management implementation where the session cookie contains only a cleartext username without integrity protection or randomness. An unauthenticated remote attacker can forge this cookie to impersonate any user, including privileged accounts, to bypass the authentication checks located in 'checkLogin' (within 'libwebcmn.so') and 'networkDiag.cgi'. Successful exploitation can lead to root-level command execution.

## Attack Chain

1. Attacker performs reconnaissance to identify default account names such as Admin or sftp_user.
2. Attacker crafts a malicious HTTP request with a forged session cookie containing the target username.
3. The web application receives the forged cookie and fails to validate integrity or session authenticity.
4. The 'checkLogin' function in 'libwebcmn.so' incorrectly validates the session based on the forged cookie.
5. The attacker gains authenticated access to 'networkDiag.cgi'.
6. Attacker leverages 'networkDiag.cgi' functionality to execute arbitrary commands with root privileges.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full administrative access and execute arbitrary commands as the root user, leading to a complete compromise of the affected network appliance.

## Recommendation

1. Upgrade Sunhillo SureLine to version 9.1.5 or later immediately.
2. Restrict access to the SureLine management web interface to trusted management networks only to minimize exposure to unauthenticated attackers.
