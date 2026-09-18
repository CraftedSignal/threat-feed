---
title: Insufficient Entropy Vulnerability in Synology DiskStation Manager Login Logic
slug: 2026-09-synology-dsm-entropy
description: Synology DiskStation Manager (DSM) contains an insufficient entropy vulnerability in its login logic that allows remote, unauthenticated attackers to perform arbitrary file read/write operations and trigger a denial-of-service condition.
date: "2026-09-18T10:04:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:synology:diskstation_manager:*:*:*:*:*:*:*:*
vendors:
  - Synology
products:
  - DiskStation Manager (< 7.2.1-69057-12, < 7.2.2-72806-9, < 7.3.2-86009-4, < 7.4-90075)
cves:
  - id: CVE-2026-13639
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13639
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Synology DiskStation Manager to version 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4, or 7.4-90075.
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies these versions address CVE-2026-13639.
  mitigation_plan:
    - priority: immediate
      action: Remove DSM management interface access from the public internet.
      owner: IT Operations
      addresses: CVE-2026-13639
      evidence: The vulnerability allows remote unauthenticated access.
---

Synology DiskStation Manager (DSM) is affected by a critical vulnerability categorized as insufficient entropy within the system's authentication and login logic. This flaw, tracked as CVE-2026-13639, enables remote, unauthenticated attackers to manipulate session generation or authentication tokens due to predictable or weak entropy sources. Exploitation of this vulnerability grants unauthorized actors the ability to read or write arbitrary files on the underlying filesystem, potentially leading to full system compromise. Additionally, attackers can leverage this flaw to induce a denial-of-service (DoS) condition, rendering the NAS device unresponsive. The vulnerability affects multiple versions of DSM, including those prior to 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4, and 7.4-90075. Organizations utilizing Synology NAS devices are urged to apply the vendor-provided patches immediately to mitigate the risk of remote file system exploitation.

## Impact

Successful exploitation of CVE-2026-13639 results in a complete loss of confidentiality and integrity, as attackers can access or modify sensitive data stored on the NAS, including configuration files, databases, and user documents. The capacity for remote arbitrary file write allows for persistence mechanisms or code execution if an attacker can overwrite system binaries or startup scripts. The denial-of-service vector impacts business continuity by taking critical storage infrastructure offline.

## Recommendation

Prioritized actions for security and IT operations teams:

- Upgrade all instances of Synology DiskStation Manager (DSM) to the following patched versions immediately: 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4, or 7.4-90075.
- Restrict access to the DSM management interface to trusted internal networks or via a VPN, ensuring it is not exposed directly to the internet to prevent unauthenticated remote exploitation.
- Review system logs for unauthorized configuration changes or abnormal file access patterns following the application of security updates.
