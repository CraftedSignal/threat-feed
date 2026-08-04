---
title: Critical Remote Code Execution in Check Point Security Management
slug: 2026-08-checkpoint-rce
description: Check Point security management products are vulnerable to remote code execution and security policy bypass via CVE-2026-18574, affecting multiple current and legacy versions.
date: "2026-08-04T13:37:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Check Point
products:
  - Multi-Domain Security Management
  - Security Management
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an attacker to provoke remote arbitrary code execution and a bypass of security policy.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability allows an attacker to provoke remote arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-18574
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0965/
  - https://support.checkpoint.com/results/sk/sk185222
  - https://www.cve.org/CVERecord?id=CVE-2026-18574
---

Check Point has issued a security advisory regarding a critical vulnerability, tracked as CVE-2026-18574, impacting its Security Management and Multi-Domain Security Management products. This vulnerability allows an unauthenticated remote attacker to execute arbitrary code on the target appliance and bypass established security policies. The flaw affects a wide range of current versions, including specific maintenance takes of R81.20, R82, and R82.10, as well as legacy versions R80 through R81.10. Given the role of these management platforms in overseeing perimeter and network security infrastructure, successful exploitation provides an attacker with significant control over network security posture. Defenders must prioritize patching according to Check Point sk185222 to prevent potential unauthorized access to security management consoles.

## Impact

Successful exploitation of CVE-2026-18574 allows an attacker to achieve Remote Code Execution (RCE) and bypass critical security policy controls. Because the affected software manages the security policy for the entire network, impact includes total compromise of security management operations, potential configuration changes, unauthorized access to sensitive internal network segments, and the ability to disable security logging or inspection for malicious traffic flows. Organizations utilizing these management consoles are advised to review the vendor's maintenance requirements for their specific version.

## Recommendation

* Apply the security patches referenced in Check Point security advisory sk185222 immediately for all affected Security Management and Multi-Domain Security Management versions.
* Audit access logs for the management console interface for unusual HTTP requests or unexpected administrative activity originating from non-management IP addresses.
* Restrict access to the Check Point management interfaces to authorized management workstations only, utilizing firewall rules to block internet-facing management access.
* Monitor for unauthorized process creation or unexpected network connections originating from the management server, which may indicate a post-exploitation phase following successful RCE.
