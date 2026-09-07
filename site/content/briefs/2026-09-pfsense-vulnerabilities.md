---
title: Multiple Vulnerabilities in Netgate pfSense Plus and CE
slug: 2026-09-pfsense-vulnerabilities
description: Multiple vulnerabilities in Netgate pfSense Plus and CE allow remote attackers to execute arbitrary code or conduct cross-site scripting attacks, posing a high risk to network perimeter security.
date: "2026-09-07T10:45:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - network-security
  - firewall
vendors:
  - Netgate
products:
  - pfSense Plus
  - pfSense CE
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit multiple vulnerabilities in Netgate pfSense Plus and CE to execute arbitrary code or conduct cross-site scripting attacks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Multiple vulnerabilities... allow remote attackers to execute arbitrary code.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0961
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict management interface access to internal-only subnets
      owner: IT Operations
      due: 24h
      evidence: General security best practice for perimeter firewall management interfaces.
  mitigation_plan:
    - priority: immediate
      action: Patch pfSense instances when Netgate releases the update addressing these vulnerabilities
      owner: IT Operations
      addresses: All affected versions of pfSense Plus and CE
      evidence: BSI vulnerability advisory
---

Netgate has disclosed multiple security vulnerabilities affecting both pfSense Plus and pfSense Community Edition (CE). These flaws enable unauthenticated or authenticated remote attackers to achieve arbitrary code execution on the firewall appliance or carry out cross-site scripting (XSS) attacks. Given that pfSense appliances typically reside at the network edge, successful exploitation provides an attacker with a foothold into internal networks, the ability to intercept traffic, or the capability to pivot into private segments. Organizations running affected versions of pfSense are at high risk, as compromised firewalls can be used to facilitate persistent access, exfiltration of sensitive configuration data, or complete denial of service. Defenders should prioritize patching, as these vulnerabilities threaten the integrity of the entire perimeter security stack.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise of the firewall, unauthorized access to network traffic, and potential lateral movement into protected internal infrastructure. The severity is compounded by the critical role pfSense plays as a gateway, with potential for widespread impact across enterprise or remote-work networks using these appliances as VPN concentrators or perimeter routers.

## Recommendation

- Monitor the Netgate official website for the release of security patches addressing these vulnerabilities and apply them to all appliances immediately upon availability.
- Restrict access to the pfSense WebConfigurator interface to trusted management networks only, rather than the WAN or untrusted interfaces.
- Review current firewall logs for unusual management interface access patterns or successful logins from unexpected source IP addresses.
- Ensure administrative credentials for the WebConfigurator are unique and protected by multi-factor authentication where supported.
