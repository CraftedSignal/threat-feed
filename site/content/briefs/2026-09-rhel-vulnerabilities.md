---
title: Multiple Vulnerabilities in Red Hat Enterprise Linux Components
slug: 2026-09-rhel-vulnerabilities
description: Multiple vulnerabilities in corosync, libevent, and libsoup within Red Hat Enterprise Linux could allow attackers to execute arbitrary code, bypass security controls, disclose data, or cause denial-of-service.
date: "2026-09-17T13:12:26Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:a:netapp:solidfire_\&_hci_management_node:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:solidfire_\&_hci_storage_node:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:windows_host_utilities:-:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_compute_node:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rhel
  - linux
vendors:
  - Red Hat
products:
  - Enterprise Linux (RHEL)
affected_os:
  - RHEL
cves:
  - id: CVE-2024-50602
    cvss: 5.9
    epss: 0.01033
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3419
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected RHEL systems to latest versions provided by Red Hat for CVE-2024-50602, CVE-2024-50604, and CVE-2024-50605.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends addressing identified vulnerabilities via vendor patches.
  mitigation_plan:
    - priority: immediate
      action: Upgrade corosync, libevent, and libsoup packages to versions validated by Red Hat.
      owner: IT Operations
      addresses: CVE-2024-50602, CVE-2024-50604, CVE-2024-50605
      evidence: Source identifies package-specific vulnerabilities.
---

The German Federal Office for Information Security (BSI) has reported multiple security vulnerabilities affecting specific software components within the Red Hat Enterprise Linux (RHEL) ecosystem. The affected packages include corosync, libevent, and libsoup. These vulnerabilities, tracked under CVE-2024-50602, CVE-2024-50604, and CVE-2024-50605, present varying levels of risk depending on the implementation. Potential impacts of successful exploitation range from arbitrary code execution and security control bypass to unauthorized data manipulation, data disclosure, and the induction of denial-of-service conditions. Organizations utilizing these RHEL components should prioritize patching to mitigate potential exposure, as these libraries are fundamental to various cluster and network-related operations on Linux systems.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, sensitive data exposure, or significant service disruption within enterprise environments. Given the nature of these core libraries, the impact is applicable across various RHEL-based infrastructures, including those supporting high-availability clusters and network-intensive applications.

## Recommendation

Prioritized actions for security operations and IT teams:
- Review the official Red Hat Security Advisories for the specific patch releases corresponding to CVE-2024-50602, CVE-2024-50604, and CVE-2024-50605.
- Apply security patches to all RHEL systems running the affected packages (corosync, libevent, and libsoup) immediately to remediate the vulnerability.
- Implement monitoring for abnormal service behavior or unauthorized process execution associated with cluster services or network-facing applications linked against these libraries.
