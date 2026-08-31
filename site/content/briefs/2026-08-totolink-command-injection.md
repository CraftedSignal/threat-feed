---
title: Remote Command Injection in TOTOLINK NR1800X
slug: 2026-08-totolink-command-injection
description: The TOTOLINK NR1800X router is vulnerable to remote command injection via the setUssd function in cgi-bin/cstecgi.cgi, enabling unauthenticated attackers to execute arbitrary system commands.
date: "2026-08-31T03:13:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:h:totolink:nr1800x:9.1.0u.6681_b20230703:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - network-infrastructure
vendors:
  - TOTOLINK
products:
  - NR1800X (9.1.0u.6681_B20230703)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument ussd leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-82597
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82597
rules:
  - title: Detects CVE-2026-82597 Exploitation - Command Injection in cstecgi.cgi
    description: Detects exploitation of CVE-2026-82597 via suspicious command injection characters in the ussd parameter of the /cgi-bin/cstecgi.cgi script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to cgi-bin/cstecgi.cgi
      owner: IT Operations
      due: 24h
      evidence: Source document identifies this path as the attack vector.
  mitigation_plan:
    - priority: immediate
      action: Check for firmware updates from TOTOLINK
      owner: IT Operations
      addresses: CVE-2026-82597
      evidence: Standard patching process for known vulnerabilities.
---

A command injection vulnerability, tracked as CVE-2026-82597, exists in the TOTOLINK NR1800X router running firmware version 9.1.0u.6681_B20230703. The vulnerability originates within the setUssd function of the /cgi-bin/cstecgi.cgi script. An unauthenticated remote attacker can exploit this flaw by sending a crafted HTTP request with a malicious payload injected into the ussd parameter. 

Successful exploitation allows the attacker to execute arbitrary commands with the privileges of the web server process on the affected router. Given the availability of public exploit code, the risk of exploitation by opportunistic actors is elevated. This vulnerability is critical for network perimeter security, as routers are common gateways. Defenders should note that this vulnerability does not require prior authentication, making it particularly dangerous for internet-facing devices.
