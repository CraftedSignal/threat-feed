---
brief_id: brief-2026-11-01-archer-ax17-command-injection
event_id: brief-2026-11-01-archer-ax17-command-injection
revision: 1
activity_at: "2026-11-01T23:10:24Z"
title: 'TP-Link Archer AX17: Authenticated OS command injection (CVE-2026-9151)'
slug: 2026-11-archer-ax17-command-injection
description: An authenticated OS command injection vulnerability in the TP-Link Archer AX17 router allows administrative LAN users to achieve root command execution via malicious OpenVPN client profile descriptions.
date: "2026-11-01T23:10:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:tp_link:archer_ax17_v1:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-device
vendors:
  - TP-Link
products:
  - Archer AX17 v1 (< 1.5.0 Build 20260605)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: The payload is passed to grep and sed which the web server runs as root, allowing OS command injection.
    confidence_band: high
cves:
  - id: CVE-2026-9151
    epss: 0.01069
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=83FC3E00-5EE7-522E-AF8C-CE2B7BCFF186
  - https://sploitus.com/exploit?id=83FC3E00-5EE7-522E-AF8C-CE2B7BCFF186&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Archer AX17 v1 routers to firmware version 1.5.0 Build 20260605.
      owner: IT Operations
      due: 48h
      evidence: Fixed version provided in advisory.
  hunt_leads:
    - lead: Identify authenticated administrative sessions followed by unusual VPN configuration imports containing non-alphanumeric characters in the description field.
      technique_id: T1059.004
      data_needed:
        - Router administrative access logs
        - VPN configuration import logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploit relies on injecting backticks into the description field during profile import.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Archer AX17 v1 to firmware 1.5.0 Build 20260605
      owner: IT Operations
      addresses: CVE-2026-9151
      evidence: Provided as the fixed version in the source.
---

CVE-2026-9151 is an authenticated OS command injection vulnerability in the Archer AX17 v1 VPN client import functionality. The issue arises because the profile description field is insufficiently sanitized and later processed by system commands (`grep` and `sed`) running with root privileges. An authenticated administrative session from the LAN is required to exploit this.

## Attack Chain
1. Attacker establishes an authenticated administrative session on the LAN.
2. Attacker triggers the VPN client import functionality on the router.
3. Attacker submits a crafted OpenVPN profile description containing a payload using backticks and `${IFS}` to bypass input filtering (e.g., `` `sleep${IFS}1` ``).
4. The router stores the malicious string as a filename in `/etc/openvpn/.ovpn`.
5. The application writes the path to `/tmp/ovpn_curr_edit`.
6. The web server executes `grep` and `sed` commands using the unquoted path from `/tmp/ovpn_curr_edit`.
7. The system shell interprets the injected backticks as commands, executing the payload with root privileges.

## Impact
Successful exploitation allows for full command execution on the router as the root user, potentially leading to a complete compromise of the network device.

## Recommendation
- Update Archer AX17 v1 firmware to version 1.5.0 Build 20260605 or later.
- Limit administrative access to the router web interface to trusted management subnets or hardened endpoints to mitigate the risk of an attacker gaining the required administrative session.
- Audit logs for unexpected administrative logins or configuration changes on network devices.
