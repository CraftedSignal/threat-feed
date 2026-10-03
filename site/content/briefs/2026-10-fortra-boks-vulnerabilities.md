---
title: Critical Vulnerabilities Patched in Fortra Core Privileged Access Manager (BoKS)
slug: 2026-10-fortra-boks-vulnerabilities
description: Fortra released patches for three critical vulnerabilities in its Core Privileged Access Manager (BoKS) software, addressing authentication bypass, command injection, and memory corruption flaws.
date: "2026-10-03T11:59:13Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:fortra:core_privileged_access_manager:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - privileged-access-management
vendors:
  - Fortra
products:
  - Core Privileged Access Manager (BoKS)
affected_os:
  - Linux
  - Unix
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The second critical bug, CVE-2026-79898... is a command injection defect in crlserver that could allow an authenticated user to substitute shell commands that would be processed as root on the BoKS Master.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CVE-2026-79898... allow an authenticated user to substitute shell commands that would be processed as root on the BoKS Master.
    confidence_band: high
cves:
  - id: CVE-2026-79901
    cvss: 9.9
    epss: 0.00266
  - id: CVE-2026-79898
    cvss: 9.1
    epss: 0.00978
  - id: CVE-2026-12627
    cvss: 9.8
    epss: 0.00442
references:
  - https://www.securityweek.com/fortra-patches-critical-vulnerabilities-in-boks/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Core Privileged Access Manager (BoKS) to the latest version as per Fortra product security guidelines
      owner: IT Operations
      due: 24h
      evidence: Fortra has released patches for eight vulnerabilities in Core Privileged Access Manager (BoKS)
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the WSI REST and SOAP APIs to trusted management segments only
      owner: IT Operations
      addresses: CVE-2026-79898
      evidence: BCC and WSI can be accessed over the network without a local sudo or suexec rule
---

Fortra has disclosed and patched eight vulnerabilities affecting its Core Privileged Access Manager (BoKS), a centralized management solution for Unix and Linux environments. Among the eight, three are critical in severity and require immediate attention. CVE-2026-79901 (CVSS 9.9) allows for authentication bypass because Active Directory service account passwords are generated using a predictable pseudo-random sequence seeded with the current Unix timestamp. CVE-2026-79898 (CVSS 9.1) is a command injection flaw in the 'crlserver' component that can be exploited via BCC or the WSI REST/SOAP API to execute arbitrary commands as root. Finally, CVE-2026-12627 (CVSS 9.8) is a stack buffer overflow in the autoregistration functionality that could lead to memory corruption. While Fortra has not observed exploitation in the wild, the administrative nature of the impacted software makes these high-value targets for adversaries seeking to compromise privileged access infrastructure.

## Impact

Successful exploitation of these vulnerabilities could result in full administrative compromise of the BoKS environment, enabling unauthorized access to managed Unix/Linux fleets, privilege escalation to root, and potential persistence via memory corruption. The software is used for sensitive policy enforcement and access control, meaning impacted organizations risk the integrity and confidentiality of their privileged identity management infrastructure.

## Recommendation

- Patch all deployments of Fortra Core Privileged Access Manager (BoKS) immediately by applying the vendor-supplied updates.
- Audit access to the WSI REST and SOAP APIs to ensure only authorized endpoints can interact with the 'crlserver' component.
- Review Active Directory service account management policies for BoKS to identify potential reliance on the vulnerable 'keytab' generation process.
- Monitor logs for unauthorized access attempts targeting BoKS administrative interfaces or API endpoints.
