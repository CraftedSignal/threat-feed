---
brief_id: brief-2024-01-03-release-agent-container-escape
event_id: brief-2024-01-03-release-agent-container-escape
revision: 1
activity_at: "2024-01-03T12:00:00Z"
title: Potential Container Escape via Modified release_agent File
slug: 2024-01-release-agent-container-escape
description: Modification of the CGroup release_agent file from inside a privileged container can allow an attacker with SYS_ADMIN capabilities to escalate privileges and escape to the host machine.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-02T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*
  - cpe:2.3:a:google:kubernetes_engine:-:*:*:*:*:*:*:*
  - cpe:2.3:a:hp:onesphere:-:*:*:*:*:*:*:*
  - cpe:2.3:a:linuxcontainers:lxc:*:*:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:*:*:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc2:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc3:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc4:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc5:*:*:*:*:*:*
  - cpe:2.3:a:linuxfoundation:runc:1.0.0:rc6:*:*:*:*:*:*
  - cpe:2.3:a:netapp:hci_management_node:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:solidfire:-:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:codeready_linux_builder:8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:codeready_linux_builder:8.2:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:codeready_linux_builder_for_power_little_endian:8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:codeready_linux_builder_for_power_little_endian:8.2:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:container_development_kit:3.7:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift:3.4:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift:3.5:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift:3.6:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift:3.7:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:virtualization_host:4.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc2:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_ibm_z_systems_eus:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_power_little_endian_eus:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_for_nfv_tus:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_for_nfv_tus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_for_real_time_tus:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server:7.0:*:*:*:*:*:*:*
has_poc: true
tags:
  - container-escape
  - privilege-escalation
  - linux
vendors:
  - Checkmarx
  - Docker
products:
  - Docker Hub
  - KICS
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
cves:
  - id: CVE-2022-0492
    cvss: 7.8
    epss: 0.05238
    kev: true
    kev_status: "true"
  - id: CVE-2019-5736
    cvss: 8.6
    epss: 0.59178
    kev_status: unknown
  - id: CVE-2024-21626
    cvss: 8.6
    epss: 0.05076
    kev_status: unknown
references:
  - https://blog.aquasec.com/threat-alert-container-escape
  - https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/
  - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privileged-escape-abusing-existent-release_agent-cve-2022-0492-poc1
  - https://securelist.com/container-attack-vectors/120010/
rules:
  - title: Detect release_agent Modification in Containers
    description: Detects modifications to the release_agent file within a container environment, indicating a potential container escape attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - file_event
      - linux
  - title: Detect Interactive Processes Modifying release_agent
    description: Detects modification of the `release_agent` file by an interactive process, suggesting manual intervention.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-06-01T10:01:19Z"
    level: L2
    summary: poc_available; added CVE-2019-5736 +1; OS linux
    sources:
      - securelist
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2022-0492
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This threat involves the modification of the `release_agent` file within a CGroup directory from inside a privileged container. A privileged container, typically running on Linux, is granted elevated privileges, including `SYS_ADMIN` capabilities. An attacker leveraging a privileged container mounts a CGroup directory and alters the `release_agent` file, which is a script executed on the host at the termination of any process within that CGroup. This can lead to privilege escalation and a container escape, compromising the underlying host system. This is related to CVE-2022-0492, a vulnerability that can be exploited through this technique. The Elastic Defend for Containers integration introduced in version 9.3.0 helps detect such modifications.

## Attack Chain

1.  Attacker gains access to a privileged container with `SYS_ADMIN` capabilities.
2.  The attacker mounts a CGroup directory within the container.
3.  The attacker modifies the `release_agent` file within the mounted CGroup directory, injecting malicious code.
4.  A process within the container terminates, triggering the execution of the `release_agent` script on the host.
5.  The host executes the attacker-controlled code contained in the modified `release_agent` file.
6.  The attacker gains code execution on the host system.
7.  The attacker leverages the gained code execution to escalate privileges on the host.
8.  The attacker achieves a container escape and compromises the host.

## Impact

Successful exploitation allows attackers to escape the container and gain arbitrary code execution on the host system. This can lead to a full compromise of the host, potentially affecting other containers and sensitive data residing on the machine. The impact can range from data exfiltration and denial of service to complete system takeover, depending on the permissions and access of the compromised host account.

## Recommendation

*   Deploy the "Potential release_agent Container Escape Detected via Defend for Containers" rule provided by Elastic Defend for Containers (version 9.3.0+) to detect malicious modifications of the `release_agent` file.
*   Monitor file changes on Linux hosts, specifically targeting the `release_agent` file, using the file integrity monitoring capabilities of your EDR or SIEM solution to surface unexpected modifications.
*   Reduce the attack surface by limiting the number of privileged containers and revoking unnecessary `SYS_ADMIN` capabilities from containers to reduce the risk of exploitation.
*   Review system logs and audit logs on the host for any signs of unauthorized access or privilege escalation attempts that coincide with the alert timestamp related to this attack to prevent further escalation.
