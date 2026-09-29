---
title: Critical Vulnerabilities in Lantronix G520 Series Cellular Gateway
slug: 2026-09-lantronix-gateway
description: Multiple vulnerabilities in Lantronix G520 Series Cellular Gateway firmware allow remote, unauthenticated attackers to execute arbitrary code with root privileges by manipulating update metadata or injecting unsigned malicious packages.
date: "2026-09-29T16:25:38Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ics
  - cve
  - firmware-vulnerability
  - remote-code-execution
vendors:
  - Lantronix
products:
  - G520 Series Cellular Gateway (2.6.0.4R6_stable)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker able to influence update metadata could exploit these conditions to execute arbitrary code within the administrative context of the device.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The same authenticated origin provides an interface capable of executing system-level commands with root privileges.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-01
  - https://www.cve.org/CVERecord?id=CVE-2026-84409
  - https://www.cve.org/CVERecord?id=CVE-2026-91191
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Upgrade Lantronix G520 Series firmware to 2.6.0.7R6
      owner: IT Operations
      due: 24h
      evidence: Remediation guidance provided by CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Remove device management interfaces from public internet exposure
      owner: Network Security
      addresses: CVE-2026-84409, CVE-2026-91191
      evidence: Recommended practices section of the CISA advisory
---

Lantronix G520 Series Cellular Gateway firmware version 2.6.0.4R6_stable contains two critical vulnerabilities that expose devices to full remote compromise. CVE-2026-84409 relates to an insecure update mechanism that fetches metadata over unencrypted HTTP, which is subsequently rendered in a web interface without proper neutralization, leading to Cross-Site Scripting (XSS). An attacker can leverage this to execute arbitrary commands as root within the administrative context. 

Additionally, CVE-2026-91191 allows for the installation of malicious software packages due to improper signature verification and the inclusion of production private keys within the public SDK. By exploiting these flaws, an attacker can bypass package integrity checks and deploy arbitrary, malicious code with root-level access during the device boot or update process. These vulnerabilities pose significant risks to critical infrastructure sectors, including energy, water, and transportation, where such gateways are deployed.

## Impact

Successful exploitation could result in complete loss of device control, persistent access for attackers, and the ability to pivot into sensitive operational networks. As these devices are typically deployed at the edge of industrial networks, compromise could lead to operational disruption, data exfiltration, or the unauthorized manipulation of industrial control processes. There are no reported cases of active exploitation in the wild as of the date of publication.

## Recommendation

Prioritized actions for security operations and IT teams:
- Upgrade all instances of Lantronix G520 Series Cellular Gateways to firmware version 2.6.0.7R6 immediately to remediate both CVE-2026-84409 and CVE-2026-91191.
- Isolate cellular gateways from the public internet using firewalls; ensure that management interfaces are only accessible via secure, authenticated VPN tunnels.
- Implement egress traffic monitoring for gateway management traffic to identify connections to untrusted or unauthorized update servers.
- Disable unneeded services on gateway devices to reduce the attack surface.
