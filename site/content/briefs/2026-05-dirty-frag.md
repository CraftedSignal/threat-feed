---
brief_id: brief-2026-05-09-dirty-frag
event_id: brief-2026-05-09-dirty-frag
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:ff4216fbc0d1f8312e11a50641e3985bbe5651a17f4f0bc35b29827833565821
    summary: exploited:true; KEV CVE-2026-31431; KEV CVE-2022-0847; KEV CVE-2021-4034
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Dirty Frag Linux Kernel Local Privilege Escalation Vulnerability
slug: 2026-05-dirty-frag
description: The Dirty Frag vulnerability (CVE-2026-43284 and CVE-2026-43500) is a Linux kernel local privilege escalation that allows an unprivileged local user to gain root privileges by exploiting flaws in the networking subsystem to overwrite protected file contents in the page cache.
date: "2026-05-08T16:28:10Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2022-04-25T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:polkit_project:polkit:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:enterprise_linux_server_update_services_for_sap_solutions:7.6:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:enterprise_linux_server_update_services_for_sap_solutions:7.7:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform:4.0:*:*:*:*:*:*:*
  - cpe:2.3:o:amazon:amazon_linux:-:*:*:*:*:*:*:*
  - cpe:2.3:o:canonical:ubuntu_linux:-:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:13.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.3:-:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.3:rc7:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.3:rc8:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc6:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc2:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.3:*:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.4:*:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.5:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:10.1:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_desktop:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems_eus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems_eus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_big_endian:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian_eus:8.1:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian_eus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian_eus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time:8:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_for_nfv:8:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_for_nfv_tus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_for_nfv_tus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_tus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_tus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_scientific_computing:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server:6.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server_aus:7.3:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server_aus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server_aus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server_for_power_little_endian_update_services_for_sap_solutions:8.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=34313900-78E3-563B-99E6-155D8793C3A9&utm_source=rss&utm_medium=rss
tags:
  - linux
  - privilege-escalation
  - vulnerability
  - dirty_frag
vendors:
  - AlmaLinux
  - Amazon
  - Canonical
  - CentOS
  - Debian
  - Fedora
  - Microsoft
  - openSUSE
  - Oracle
  - Red Hat
  - Rocky Linux
  - SUSE
  - Ubuntu
products:
  - Alma Linux
  - AlmaLinux
  - Amazon Linux
  - Amazon Linux kernels
  - CentOS Stream
  - Debian
  - Fedora
  - GLPI
  - kernel
  - Linux kernel
  - Microsoft Defender
  - OpenShift
  - openSUSE
  - Oracle Linux
  - Red Hat Enterprise Linux
  - RHEL
  - Rocky Linux
  - SUSE Linux Enterprise
  - Ubuntu
affected_os:
  - Ubuntu
  - RHEL
  - CentOS Stream
  - AlmaLinux
  - Fedora
  - openSUSE
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-43284
    cvss: 8.8
    epss: 7e-05
    kev_status: unknown
  - id: CVE-2026-43500
    cvss: 7.8
    epss: 0.0001
    kev_status: unknown
  - id: CVE-2026-31431
    cvss: 7.8
    epss: 0.0257
    kev: true
    kev_status: "true"
  - id: CVE-2022-0847
    cvss: 7.8
    epss: 0.81212
    kev: true
    kev_status: "true"
  - id: CVE-2021-4034
    cvss: 7.8
    epss: 0.87351
    kev: true
    kev_status: "true"
references:
  - https://ccb.belgium.be/advisories/warning-dirty-frag-new-linux-local-privilege-escalation-vulnerability-was-disclosed
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43284
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43500
  - https://almalinux.org/blog/2026-05-07-dirty-frag/
  - https://aws.amazon.com/security/security-bulletins/rss/2026-027-aws/
  - https://security-tracker.debian.org/tracker/CVE-2026-43284
  - https://access.redhat.com/security/vulnerabilities/RHSB-2026-003
  - https://ubuntu.com/blog/dirty-frag-linux-vulnerability-fixes-available
  - https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc
  - https://ccb.belgium.be/advisories/warning-copy-fail-getting-root-major-linux-distributions-patch-immediately
  - https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/
  - https://cyber.gc.ca/en/alerts-advisories/al26-011-vulnerabilities-affecting-linux-cve-2026-43284-cve-2026-43500
  - https://blog.qualys.com/product-tech/vulnmgmt-detection-response/2026/05/09/dirty-frag-using-the-page-caches-as-an-attack-surface
  - https://sploitus.com/exploit?id=34313900-78E3-563B-99E6-155D8793C3A9&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/new-dirty-frag-linux-vulnerability-possibly-exploited-in-attacks/
  - https://www.bleepingcomputer.com/news/security/new-fragnesia-linux-flaw-lets-attackers-gain-root-privileges/
rules:
  - title: Detect Potential Dirty Frag Exploitation
    description: Detects CVE-2026-43284 and CVE-2026-43500 exploitation - monitors for suspicious network activity potentially related to the 'Dirty Frag' vulnerability exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
  - title: Detect Modification of /etc/passwd or /etc/shadow
    description: Detects modification of critical system files /etc/passwd or /etc/shadow, which may indicate a successful privilege escalation attempt after CVE-2026-43284 or CVE-2026-43500 exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-05-08T18:36:28Z"
    level: L1
    summary: new product
    sources:
      - cccs
  - at: "2026-05-09T07:23:58Z"
    level: L2
    summary: added CVE-2022-0847
    sources:
      - qualys-threat-research
  - at: "2026-05-09T20:02:26Z"
    level: L2
    summary: added CVE-2021-4034 +1
    sources:
      - sploitus
  - at: "2026-05-11T08:16:36Z"
    level: L2
    summary: added CVE-2026-43500
    sources:
      - securityweek
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-31431; KEV CVE-2022-0847; KEV CVE-2021-4034
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The "Dirty Frag" vulnerability, disclosed in May 2026, affects the Linux kernel and allows a local, unprivileged user to escalate privileges to root. The vulnerability chains together two separate kernel flaws within the networking subsystem. Successful exploitation enables attackers to overwrite protected file contents within the Linux page cache, bypassing standard write permission checks. This page cache corruption can be leveraged for deterministic root privilege escalation. The vulnerability belongs to the same class of page-cache corruption issues as Dirty Pipe and "Copy Fail". While an official patched kernel has not been released, most major Linux distributions have backported patches in available updates. No in-the-wild exploitation has been reported, but similar vulnerabilities have been exploited rapidly after disclosure.

## Attack Chain

1.  An unprivileged local user logs into the system, potentially via SSH or a local console.
2.  The attacker exploits the first networking subsystem flaw to create a fragmented network packet.
3.  The attacker exploits the second networking subsystem flaw, triggering improper handling of the fragmented packet.
4.  These flaws allow the attacker to overwrite data in the Linux page cache without proper write permissions.
5.  The attacker targets sensitive files, such as `/etc/passwd` or `/etc/shadow`, within the page cache.
6.  The attacker overwrites the targeted files with malicious content, such as adding a new root user or modifying existing user credentials.
7.  The attacker uses the modified credentials to authenticate as root or escalate privileges to root.
8.  The attacker gains full control of the system, allowing for arbitrary code execution, data exfiltration, and other malicious activities.

## Impact

Successful exploitation of the "Dirty Frag" vulnerability grants an attacker complete control over the affected Linux system. This can lead to data breaches, system downtime, and further propagation of malicious activities within the network. The vulnerability affects a wide range of Linux distributions, potentially impacting a large number of servers, workstations, and embedded devices. Given the CVSS score of 7.8, the impact is considered high due to the potential compromise of confidentiality, integrity, and availability.

## Recommendation

*   Apply available patches from your Linux distribution to address CVE-2026-43284 and CVE-2026-43500 with the highest priority.
*   If patching is not immediately feasible, implement mitigation measures as recommended by your Linux distribution, acknowledging potential impacts on IPSEC and AFS functionality.
*   Deploy the Sigma rule `Detect Potential Dirty Frag Exploitation` to identify suspicious network activity that may indicate an attempted exploitation.
*   Enable auditd logging on Linux systems to capture system calls and file modifications, providing valuable data for incident response and forensic analysis, as required by the Sigma rule.
*   Monitor for unexpected modifications to critical system files such as `/etc/passwd` and `/etc/shadow`, which could indicate successful exploitation.
