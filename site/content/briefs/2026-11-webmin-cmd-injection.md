---
brief_id: brief-2026-11-10-webmin-cmd-injection
event_id: brief-2026-11-10-webmin-cmd-injection
revision: 1
activity_at: "2026-11-10T04:02:33Z"
title: 'Webmin: OS command injection in samba/save_euser.cgi (CVE-2026-125391)'
slug: 2026-11-webmin-cmd-injection
description: Webmin versions up to 2.670 contain an OS command injection vulnerability in the samba/save_euser.cgi script, allowing authenticated users to execute arbitrary commands as root via the opts parameter.
date: "2026-11-10T04:02:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*
vendors:
  - Webmin
products:
  - Webmin (<= 2.670)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Attackers can embed shell metacharacters in account option flags passed by create_user and modify_user to backquote_logged, executing commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-125391
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125391
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify unexpected child processes spawned by the Webmin web server process
      technique_id: T1059.004
      data_needed:
        - Process creation logs (Sysmon Event ID 1 or Auditd logs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can embed shell metacharacters in account option flags passed by create_user and modify_user to backquote_logged, executing commands as root.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Webmin to the version following 2.670
      owner: IT Operations
      addresses: CVE-2026-125391
      evidence: Webmin through 2.670 contains an OS command injection vulnerability
---

Webmin versions through 2.670 are vulnerable to OS command injection within the `samba/save_euser.cgi` script. The vulnerability stems from the insufficient validation of the `opts` parameter. Authenticated users with permissions to manage Samba users can inject shell metacharacters into the account option flags processed by `create_user` and `modify_user` functions, leading to command execution with root privileges.

## Impact
Successful exploitation allows an authenticated attacker to execute arbitrary commands on the underlying host operating system with root-level privileges.

## Recommendation
- Upgrade Webmin to a version beyond 2.670 once a vendor security patch is available.
- Audit administrative access to the Webmin Samba module to restrict it to trusted administrative accounts.
- Implement the suggested hunt lead to monitor for suspicious command execution originating from the Webmin process context.
