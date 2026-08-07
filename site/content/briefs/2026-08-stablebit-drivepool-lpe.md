---
title: Local Privilege Escalation in StableBit DrivePool
slug: 2026-08-stablebit-drivepool-lpe
description: StableBit DrivePool version 2.3.13.1687 contains a local privilege escalation vulnerability in the DrivePoolService component stemming from improper permission management and insecure deserialization.
date: "2026-08-07T05:30:55Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - StableBit
products:
  - DrivePool (2.3.13.1687)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The attack must be carried out locally. The exploit has been disclosed publicly and may be used.
    confidence_band: high
cves:
  - id: CVE-2026-19191
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19191
  - https://vuldb.com/vuln/386709
  - https://winslow1984.com/books/cve-collection/page/stablebit-drivepool-23131687-local-privilege-escalation-via-insecure-deserialization
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of StableBit DrivePool 2.3.13.1687 to the latest version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-19191 CVSS 7.8 rating
  hunt_leads:
    - lead: Identify local users with permission to interact with DrivePool.Service.exe or access its installation directory.
      technique_id: T1068
      data_needed:
        - File system ACL logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves permission issues in the DrivePoolService component.
  mitigation_plan:
    - priority: immediate
      action: Restrict local user access to the DrivePool installation folder and service configuration.
      owner: IT Operations
      addresses: CVE-2026-19191
      evidence: Vulnerability linked to permission issues in DrivePool.Service.exe
---

StableBit DrivePool version 2.3.13.1687 is susceptible to a high-severity local privilege escalation vulnerability, tracked as CVE-2026-19191. The vulnerability is located within the DrivePoolService component, specifically within the DrivePool.Service.exe executable. According to vulnerability disclosures, the flaw is rooted in incorrect privilege assignment and permission issues, potentially exacerbated by insecure deserialization.

An attacker who has already achieved local access to a system running the affected version can exploit this vulnerability to manipulate the service and gain elevated privileges. The exploit has been disclosed publicly, increasing the risk of abuse by threat actors looking to gain administrative control after initial foothold establishment. Organizations utilizing this software on Windows environments should verify versioning and prioritize patching or isolating the service until a secure version is deployed.

## Impact

Successful exploitation allows a local user to escalate privileges to the level of the DrivePoolService, which typically operates with elevated system-level permissions. This can result in complete system compromise, unauthorized data access, and persistent control over the host. The vulnerability is rated with a CVSS 3.1 base score of 7.8, reflecting the significant risk of full administrative access once local access is achieved.

## Recommendation

* Identify all systems in the environment running StableBit DrivePool version 2.3.13.1687.
* Update StableBit DrivePool to the latest patched version to remediate CVE-2026-19191.
* Monitor file integrity for C:\Program Files\StableBit\DrivePool\DrivePool.Service.exe to detect unauthorized modifications or suspicious process behavior associated with the service.
* Implement strict access control lists (ACLs) on the DrivePool service directory to prevent unauthorized local users from modifying or interacting with the service executable.
