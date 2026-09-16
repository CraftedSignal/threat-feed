---
title: Remote Code Execution Vulnerability in Netgate pfSense
slug: 2026-09-pfsense-rce
description: A remote code execution vulnerability in Netgate pfSense CE and Plus allows unauthenticated attackers to execute arbitrary code on affected firewall appliances.
date: "2026-09-16T13:06:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - firewall
vendors:
  - Netgate
products:
  - pfSense CE (< 2.9.0)
  - pfSense Plus (< 26.07)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Une vulnérabilité a été découverte dans Netgate pfSense. Elle permet à un attaquant de provoquer une exécution de code arbitraire à distance.
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1181/
  - https://docs.netgate.com/downloads/pfSense-SA-26_22.webgui.asc
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade pfSense CE to 2.9.0 or pfSense Plus to 26.07 or later.
      owner: IT Operations
      addresses: Netgate pfSense vulnerabilities in versions prior to 2.9.0 and 26.07.
      evidence: Netgate security advisory pfSense-SA-26_22.
---

The French National Cybersecurity Agency (ANSSI) has released a security advisory regarding a remote code execution (RCE) vulnerability in Netgate pfSense software. This vulnerability, documented in Netgate security advisory pfSense-SA-26_22, affects pfSense Community Edition (CE) versions prior to 2.9.0 and pfSense Plus versions prior to 26.07. An unauthenticated attacker may leverage this vulnerability to gain unauthorized remote code execution capabilities on the underlying operating system of the firewall appliance. Given that pfSense devices typically act as the security perimeter for internal networks, successful exploitation poses a severe risk to organizational infrastructure, potentially allowing for full system compromise, network traffic interception, or lateral movement into protected network segments.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code on the affected pfSense firewall appliances. This can lead to a total compromise of the security appliance, potentially enabling unauthorized access to internal network traffic, manipulation of firewall rules, and the ability to pivot into the internal network environment. All organizations utilizing pfSense CE version 2.9.0 or earlier, or pfSense Plus version 26.07 or earlier, are potentially vulnerable and should prioritize patching.

## Recommendation

- Patch affected firewall appliances immediately by updating to pfSense CE 2.9.0 or pfSense Plus 26.07 or later versions as specified in the Netgate security advisory pfSense-SA-26_22.
- Restrict access to the pfSense web configuration interface to trusted management networks only to minimize the exposure of this vulnerability to unauthenticated external actors.
- Review firewall logs for unusual management interface access patterns from unauthorized or external IP addresses.
