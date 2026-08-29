---
title: Denial of Service Vulnerability in GNU C Library
slug: 2026-08-glibc-dos
description: A local attacker can exploit a vulnerability in the GNU C Library (glibc) to cause application crashes or service instability, resulting in a Denial of Service.
date: "2026-08-11T11:35:50Z"
lastmod: "2026-08-29T12:44:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h300s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h500s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h700s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h410s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h410c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h610c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h610s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_h615c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_compute_node:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KYOTOZX-CVE-2024-2961-REMOTE-FILE-READ&utm_source=rss&utm_medium=rss
tags:
  - denial-of-service
  - linux
  - vulnerability
vendors:
  - GNU
  - NetApp
  - Debian
products:
  - GNU C Library
  - Active IQ Unified Manager
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A local attacker can exploit a vulnerability in the GNU C Library (glibc) to cause application crashes or service instability, resulting in a Denial of Service.
    confidence_band: high
cves:
  - id: CVE-2024-2961
    cvss: 7.3
    epss: 0.8833
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2740
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KYOTOZX-CVE-2024-2961-REMOTE-FILE-READ&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Apply patches for glibc provided by the distribution maintainer
      owner: IT Operations
      addresses: CVE-2024-2961
      evidence: Source advisory recommends applying updates.
updates:
  - at: "2026-08-29T12:44:21Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KYOTOZX-CVE-2024-2961-REMOTE-FILE-READ&utm_source=rss&utm_medium=rss
---

The BSI has reported a vulnerability within the GNU C Library (glibc), identified as CVE-2024-2961. This flaw permits a local attacker to trigger a Denial of Service (DoS) condition on affected Linux systems. The vulnerability stems from improper handling of specific inputs by the library during runtime, which can cause applications linked against the compromised version of glibc to crash or become unstable. Given that glibc is a fundamental component of most Linux distributions, this vulnerability impacts a wide range of services and applications that rely on its core functions for memory management, string manipulation, and system calls. Defenders should prioritize patching the glibc packages provided by their distribution maintainers to mitigate the risk of local service disruption.

## Impact

Successful exploitation of this vulnerability results in the disruption of availability for critical services and applications running on the affected Linux host. This can lead to service outages, potential data loss during unexpected crashes, and operational downtime. Because the vulnerability requires local access, it is particularly relevant in multi-user environments or systems where untrusted local users have the ability to execute code.

## Recommendation

Prioritized, concrete actions for detection engineering and system administration teams:
- Update the GNU C Library (glibc) packages via the system package manager immediately upon the release of patched versions by the OS distribution vendor.
- Review system logs for frequent, unexpected process crashes (e.g., segment faults or core dumps) for services that may be triggering the vulnerable code paths.
- Audit multi-user Linux environments to restrict execution permissions for untrusted users to minimize the impact of local exploitation.
