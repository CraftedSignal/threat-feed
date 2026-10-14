---
title: Multiple Vulnerabilities in Fortinet Products
slug: 2026-10-fortinet-vulnerabilities
description: Multiple vulnerabilities across several Fortinet products, including FortiOS and FortiManager, permit remote code execution, privilege escalation, and denial-of-service.
date: "2026-10-14T16:21:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - fortinet
  - network-security
vendors:
  - Fortinet
products:
  - FortiAnalyzer Cloud (>7.2.1 and <7.2.12, >7.4.1 and <7.4.8, >7.6.2 and <7.6.5)
  - FortiAnalyzer (<7.4.8, 7.6.x < 7.6.5)
  - FortiManager (<7.4.7, 7.6.x < 7.6.7, 8.0.x < 8.0.1)
  - FortiManager Cloud (>7.6.2 and <7.6.7)
  - FortiOS (8.0.x < 8.0.1, < 7.6.9)
  - FortiProxy (< 7.6.7)
  - FortiSandbox Cloud (< 5.0.7, 5.2.x < 5.2.2)
  - FortiSandbox PaaS (< 5.0.7)
  - FortiSandbox (< 5.0.7, 5.2.x < 5.2.2)
  - FortiSwitch (< 7.6.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: De multiples vulnérabilités ont été découvertes dans les produits Fortinet... [permettant] une élévation de privilèges.
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1306/
  - https://www.fortiguard.com/psirt/FG-IR-26-176
  - https://www.fortiguard.com/psirt/FG-IR-26-177
  - https://www.fortiguard.com/psirt/FG-IR-26-178
  - https://www.fortiguard.com/psirt/FG-IR-26-179
  - https://www.fortiguard.com/psirt/FG-IR-26-181
  - https://www.fortiguard.com/psirt/FG-IR-26-182
  - https://www.fortiguard.com/psirt/FG-IR-26-185
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all affected Fortinet devices to patched versions listed in the vendor bulletins.
      owner: IT Operations
      due: 24h
      evidence: Source provides specific vulnerable ranges and directs to vendor patches.
  mitigation_plan:
    - priority: immediate
      action: Patch to versions specified in FG-IR-26-176 through FG-IR-26-185.
      owner: IT Operations
      addresses: Multiple CVEs affecting Fortinet products
      evidence: Source documentation
---

On October 14, 2026, the French National Cybersecurity Agency (ANSSI) reported multiple critical vulnerabilities affecting a wide range of Fortinet products. These flaws impact various versions of FortiAnalyzer, FortiManager, FortiOS, FortiProxy, FortiSandbox, and FortiSwitch. The vulnerabilities allow remote attackers to execute arbitrary code, perform privilege escalation, bypass security policies, or induce denial-of-service conditions. Organizations utilizing these products should audit their firmware versions immediately and apply the patches referenced in the specific Fortinet security bulletins (FG-IR-26-176 through FG-IR-26-185).

## Impact

Successful exploitation of these vulnerabilities could lead to full system compromise, unauthorized access to network configurations, or service outages. Given the ubiquity of Fortinet appliances at network perimeters, unpatched systems are at high risk of exploitation. These flaws affect core security infrastructure used by enterprises and service providers to manage traffic and secure network perimeters.

## Recommendation

* Immediately audit all FortiAnalyzer, FortiManager, FortiOS, FortiProxy, FortiSandbox, and FortiSwitch deployments against the affected version lists.
* Apply vendor-supplied patches as documented in Fortinet security bulletins FG-IR-26-176, FG-IR-26-177, FG-IR-26-178, FG-IR-26-179, FG-IR-26-181, FG-IR-26-182, and FG-IR-26-185.
* Review administrative access logs for unusual activity originating from internal or external sources on management interfaces of Fortinet appliances.
