---
title: 'CVE-2026-68160: Out-of-Bounds Read in Ceph ceph_handle_caps'
slug: 2026-08-ceph-oob-read
description: A vulnerability in the Ceph ceph_handle_caps function allows for an out-of-bounds read during the pre-authentication phase, potentially leading to denial-of-service or memory disclosure.
date: "2026-08-11T10:37:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - ceph
  - memory-safety
vendors:
  - Ceph
products:
  - Ceph
cves:
  - id: CVE-2026-68160
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68160
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Upgrade Ceph software to the latest version to patch CVE-2026-68160
      owner: IT Operations
      addresses: CVE-2026-68160
      evidence: Source advisory
---

CVE-2026-68160 identifies an out-of-bounds read vulnerability within the Ceph storage system, specifically located in the ceph_handle_caps() function. The flaw occurs during the pre-authentication phase when processing snaptrace data. An attacker capable of interacting with the Ceph service during this early handshake stage could trigger the vulnerability. If successfully exploited, this defect may result in a denial-of-service condition due to application crashes or potentially lead to the disclosure of sensitive memory contents residing in the affected memory regions. This vulnerability is relevant to security operations teams monitoring Ceph storage clusters for unauthorized or malformed pre-authentication traffic.

## Impact

Successful exploitation could result in service instability, causing the Ceph daemon to crash, or the unauthorized access to sensitive memory. This poses a risk to organizations relying on Ceph for high-availability storage, as it could be used to disrupt data access or leak information from memory buffers.

## Recommendation

- Update Ceph installations to the latest patched version provided by the Ceph project or distribution maintainers.
- Review network access control lists (ACLs) to restrict unauthorized access to Ceph services, especially if exposed to untrusted networks.
- Monitor logs for repeated service crashes of the Ceph daemon, which may indicate exploitation attempts.
