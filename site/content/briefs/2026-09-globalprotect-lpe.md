---
title: GlobalProtect App Local Privilege Escalation Vulnerabilities
slug: 2026-09-globalprotect-lpe
description: Multiple local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect application allow a local user to gain administrative privileges (SYSTEM/root) due to an untrusted search path issue.
date: "2026-09-09T18:57:59Z"
lastmod: "2026-09-10T12:54:58Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:palo_alto_networks:globalprotect_app:6.3.3:*:*:*:*:linux:*:*
  - cpe:2.3:a:palo_alto_networks:globalprotect_app:6.0.14:*:*:*:*:linux:*:*
tags:
  - vulnerability
  - privilege-escalation
  - endpoint
vendors:
  - Palo Alto Networks
products:
  - GlobalProtect App (< 6.3.3-h15, < 6.2.8-h14, < 6.0.15)
  - PAN-OS (12.2.0-12.2.2, 12.1.2-12.1.9, 11.2.0-11.2.13, 11.1.0-11.1.16, 10.2.0-10.2.18)
  - Prisma Access (12.1.2-12.1.*, 11.2.0-11.2.*, 10.2.0-10.2.*)
  - GlobalProtect App
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Multiple local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect™ app allows a local user to escalate their privileges to NT AUTHORITY\SYSTEM on Windows and root on macOS and Linux.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0307
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3283
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade GlobalProtect client on all workstations to version 6.3.3-h15 or relevant platform patch
      owner: IT Operations
      due: 72h
      evidence: Source advisory solution section
  mitigation_plan:
    - priority: immediate
      action: Upgrade PAN-OS and Prisma Access infrastructure to defined fixed versions
      owner: Network Engineering
      addresses: CVE-2026-0307
      evidence: Source Solution section
updates:
  - at: "2026-09-10T12:54:58Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3283
---

Palo Alto Networks has disclosed multiple local privilege escalation vulnerabilities (CVE-2026-0307) affecting the GlobalProtect app across Windows, macOS, and Linux platforms. The issue stems from CWE-426, an untrusted search path vulnerability, which allows a local non-administrative user to manipulate the execution flow of the application to run arbitrary commands with elevated privileges (NT AUTHORITY\SYSTEM on Windows and root on macOS/Linux). 

The vulnerability is categorized as Medium severity and is documented with a CVSS-BT score of 5.9. Exploitation requires local access, and Palo Alto Networks has confirmed that there is currently no evidence of malicious exploitation in the wild. Full remediation requires a coordinated update of both the client-side GlobalProtect application and the server-side infrastructure (PAN-OS or Prisma Access). iOS, Android, and ChromeOS versions of the app are not affected.

## Impact

Successful exploitation allows a low-privileged local user to achieve full administrative control over the affected endpoint. This can lead to total system compromise, unauthorized data access, persistence installation, and further lateral movement within the network. The scope of impact is broad due to the ubiquity of GlobalProtect clients in enterprise environments.

## Recommendation

Prioritize the deployment of updated GlobalProtect client versions across all Windows, macOS, and Linux endpoints. Concurrently, schedule and execute upgrades for all affected PAN-OS and Prisma Access infrastructure components to ensure compatibility and full mitigation.

* Upgrade GlobalProtect App on Linux, macOS, and Windows to the versions specified in the Palo Alto Networks advisory (e.g., 6.3.3-h15 or later).
* Update all PAN-OS and Prisma Access environments to the patched versions listed in the Solution section of the source advisory to ensure the infrastructure components are no longer vulnerable.
* Audit endpoint security logs for unauthorized process execution or unexpected binary loading from untrusted directories.
