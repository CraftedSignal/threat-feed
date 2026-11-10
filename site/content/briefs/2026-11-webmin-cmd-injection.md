---
brief_id: brief-2026-11-10-webmin-cmd-injection
event_id: brief-2026-11-10-webmin-cmd-injection
revision: 2
activity_at: "2026-11-10T16:31:37Z"
revision_history:
  - revision: 2
    at: "2026-11-10T16:31:37Z"
    checksum: sha256:63c379b477c5e8225e81d41299cf84d1c162e42944d7946c176dc4a7f4bcaa00
    summary: added coverage for Webmin
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - priority_signals
      - references
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4423
title: 'Webmin: OS command injection in samba/save_euser.cgi (CVE-2026-125391)'
slug: 2026-11-webmin-cmd-injection
description: Webmin versions up to 2.670 contain an OS command injection vulnerability in the samba/save_euser.cgi script, allowing authenticated users to execute arbitrary commands as root via the opts parameter.
date: "2026-11-10T04:02:33Z"
lastmod: "2026-11-10T16:30:30Z"
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
tags:
  - web-application
  - vulnerability
  - linux
vendors:
  - Webmin
products:
  - Webmin (<= 2.670)
  - Webmin
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
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4423
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  hunt_leads:
    - lead: Identify unexpected child processes spawned by the Webmin web server process
      technique_id: T1059.004
      data_needed:
        - Process creation logs (Sysmon Event ID 1 or Auditd logs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can embed shell metacharacters in account option flags passed by create_user and modify_user to backquote_logged, executing commands as root.
    - lead: Identify authenticated sessions with unusual command execution patterns
      technique_id: T1059
      data_needed:
        - Webmin access logs
        - System process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An authenticated remote attacker can exploit multiple vulnerabilities to execute arbitrary code with administrator privileges.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Webmin to the version following 2.670
      owner: IT Operations
      addresses: CVE-2026-125391
      evidence: Webmin through 2.670 contains an OS command injection vulnerability
    - priority: immediate
      action: Restrict Webmin management interface access to trusted networks
      owner: IT Operations
      addresses: Remote access to management interface
      evidence: Vulnerabilities require authentication, reducing scope to established sessions or those reachable from network
updates:
  - at: "2026-11-10T16:30:30Z"
    level: L1
    summary: added coverage for Webmin
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4423
---

Webmin versions through 2.670 are vulnerable to OS command injection within the `samba/save_euser.cgi` script. The vulnerability stems from the insufficient validation of the `opts` parameter. Authenticated users with permissions to manage Samba users can inject shell metacharacters into the account option flags processed by `create_user` and `modify_user` functions, leading to command execution with root privileges.

## Impact
Successful exploitation allows an authenticated attacker to execute arbitrary commands on the underlying host operating system with root-level privileges.

## Recommendation
- Upgrade Webmin to a version beyond 2.670 once a vendor security patch is available.
- Audit administrative access to the Webmin Samba module to restrict it to trusted administrative accounts.
- Implement the suggested hunt lead to monitor for suspicious command execution originating from the Webmin process context.
