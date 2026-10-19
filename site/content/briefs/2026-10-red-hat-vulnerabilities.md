---
title: Multiple Vulnerabilities in Red Hat Quay and Enterprise Linux
slug: 2026-10-red-hat-vulnerabilities
description: Red Hat Quay and Red Hat Enterprise Linux are affected by vulnerabilities in the pypdf and urllib3 libraries, alongside URI handling flaws, allowing remote unauthenticated attackers to perform Denial of Service or security bypasses.
date: "2026-10-19T14:07:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:redhat:quay:*:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*
  - cpe:2.3:a:exrick:xmall:1.1:*:*:*:*:*:*:*
  - cpe:2.3:a:python:urllib3:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
tags:
  - vulnerability
  - red-hat
  - linux
  - denial-of-service
vendors:
  - Red Hat
products:
  - Quay
  - Enterprise Linux
affected_os:
  - Red Hat Enterprise Linux
cves:
  - id: CVE-2023-36331
    cvss: 8.2
    epss: 0.00239
  - id: CVE-2024-37891
    cvss: 4.4
    epss: 0.01141
  - id: CVE-2023-43804
    cvss: 5.9
    epss: 0.0136
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4024
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Red Hat Quay and Red Hat Enterprise Linux components to the latest vendor-provided versions to remediate CVE-2023-36331, CVE-2024-37891, and CVE-2023-43804.
      owner: IT Operations
      addresses: CVE-2023-36331, CVE-2024-37891, CVE-2023-43804
      evidence: Source advisory confirms vulnerabilities exist in these packages and products.
---

Red Hat has identified multiple security vulnerabilities impacting Red Hat Quay and Red Hat Enterprise Linux. These flaws stem from vulnerabilities within the integrated pypdf and urllib3 libraries, as well as specific issues in URI handling mechanisms. Remote, unauthenticated attackers can leverage these weaknesses to trigger Denial of Service (DoS) conditions, effectively disrupting service availability, or bypass existing security restrictions. The affected CVEs include CVE-2023-36331, CVE-2024-37891, and CVE-2023-43804. Defenders should prioritize patching, as these libraries are common dependencies within containerized environments and enterprise infrastructure.

## Impact

Successful exploitation of these vulnerabilities allows for service degradation or unauthorized security bypasses in Red Hat-based environments. These flaws pose a risk to the availability and integrity of Red Hat Quay registries and host operating systems. The potential for DoS attacks against critical container infrastructure could lead to significant operational disruption in enterprise sectors relying on these products.

## Recommendation

- Update Red Hat Quay and Red Hat Enterprise Linux instances to the versions specified in the official Red Hat security advisories.
- Review dependencies within container images hosted on Quay to identify and update instances of pypdf and urllib3.
- Audit network ingress traffic for malformed URI patterns that may attempt to trigger resource exhaustion or bypass logic in web-facing components.
