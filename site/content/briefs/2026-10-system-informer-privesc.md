---
title: Privilege Escalation Vulnerability in System Informer phsvc
slug: 2026-10-system-informer-privesc
description: System Informer versions prior to 4.0.26241.138 contain an incorrect authorization vulnerability in the phsvc service that allows local attackers to elevate privileges to SYSTEM via privileged API calls.
date: "2026-10-08T22:14:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:system_informer:system_informer:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
vendors:
  - System Informer
products:
  - System Informer (< 4.0.26241.138)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local attacker can exploit this by executing code within a process signed with a valid Authenticode signature to communicate with the SiSvcApiPort and invoke PhSvcApiCreateService, ultimately achieving privilege escalation to SYSTEM.
    confidence_band: high
cves:
  - id: CVE-2026-107782
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107782
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade System Informer to version 4.0.26241.138 or later
      owner: IT Operations
      addresses: CVE-2026-107782
      evidence: System Informer before 4.0.26241.138 contains an incorrect authorization vulnerability
---

System Informer (formerly Process Hacker) contains an incorrect authorization vulnerability in its helper service, phsvc, tracked as CVE-2026-107782. The vulnerability exists because the phsvc service incorrectly validates the authenticity of processes attempting to connect to its privileged APIs via the SiSvcApiPort. Specifically, the service trusts any process that possesses a valid Authenticode signature, regardless of whether that process is inherently trustworthy or compromised. A local attacker can abuse this by loading malicious code into a legitimate, Microsoft-signed binary such as rundll32.exe. Once the malicious code is running within the signed context, it can establish a connection to SiSvcApiPort and invoke the PhSvcApiCreateService function. This allows the attacker to execute arbitrary code with SYSTEM-level privileges. This flaw impacts all versions of System Informer prior to 4.0.26241.138 and represents a significant privilege escalation vector for local attackers who have already gained low-privileged access to a system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escalate privileges from a low-privileged user account to the SYSTEM account. This bypasses standard Windows security boundaries, granting the attacker full control over the compromised host. This is critical for post-exploitation activities, including credential dumping, persistence establishment, and disabling security software.

## Recommendation

Update System Informer to version 4.0.26241.138 or later immediately on all endpoints where the software is deployed to address the incorrect authorization flaw in phsvc.
