---
title: Vulnerabilities in Moxa MGate Protocol Gateways
slug: 2026-10-moxa-advisory
description: Moxa has disclosed two critical vulnerabilities, CVE-2026-86325 and CVE-2026-86326, affecting MGate 3000 and 5000 series protocol gateways.
date: "2026-10-02T22:52:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - industrial-control-systems
  - vulnerability
  - ot-security
vendors:
  - Moxa
products:
  - MGate 3000 Series
  - MGate 5000 Series
cves:
  - id: CVE-2026-86325
  - id: CVE-2026-86326
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-moxa-security-advisory-av26-995
  - https://www.moxa.com/en/support/product-support/security-advisory/mpsa-269540-cve-2026-86325,-cve-2026-86326-two-vulnerabilities-in-protocol-gateways
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  mitigation_plan:
    - priority: immediate
      action: Review vendor advisory MPSA-269540 and deploy firmware patches for MGate 3000 and 5000 series
      owner: OT Security
      addresses: CVE-2026-86325, CVE-2026-86326
      evidence: Official Moxa security advisory regarding protocol gateway vulnerabilities
---

Moxa has released security advisory AV26-995 regarding two vulnerabilities identified as CVE-2026-86325 and CVE-2026-86326. These vulnerabilities impact the MGate 3000 and MGate 5000 series of protocol gateways, which are commonly utilized in industrial control systems to facilitate communication between different fieldbus and Ethernet protocols. The vulnerabilities originate within the gateway firmware, potentially exposing industrial network infrastructure to exploitation. Because these devices act as critical bridges between IT and OT environments, unpatched vulnerabilities in these gateways represent a significant risk to operational continuity and network integrity. Administrators are advised to monitor the official Moxa security portal for specific firmware update releases and apply them to all affected units within their industrial control system environment.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized access, service disruption, or unauthorized control of traffic passing through the affected MGate gateways. Given the role of these devices in industrial environments, compromise could lead to direct operational impacts, including the interruption of physical processes, loss of visibility into critical assets, or the manipulation of industrial control traffic.

## Recommendation

- Review the official Moxa security advisory MPSA-269540 for detailed mitigation steps regarding CVE-2026-86325 and CVE-2026-86326.
- Prioritize the application of firmware updates on internet-facing or perimeter-integrated MGate gateways.
- Implement network segmentation to isolate MGate 3000 and 5000 series devices from unnecessary network traffic until patching is completed.
