---
title: Multiple Vulnerabilities in util-linux
slug: 2026-08-util-linux-vulnerabilities
description: Multiple vulnerabilities in the util-linux package allow a local attacker to escalate privileges, bypass security measures, manipulate data, or trigger a denial-of-service condition.
date: "2026-08-20T13:11:02Z"
lastmod: "2026-08-26T01:01:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kernel:util-linux:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SKYLER-FERRANTE-CVE-2024-28085&utm_source=rss&utm_medium=rss
vendors:
  - Kernel.org
products:
  - util-linux
affected_os:
  - Ubuntu 22.04
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann mehrere Schwachstellen in util-linux ausnutzen, um Administratorrechte zu erlangen
    confidence_band: high
cves:
  - id: CVE-2024-28085
    cvss: 3.3
    epss: 0.02242
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2938
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SKYLER-FERRANTE-CVE-2024-28085&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update util-linux packages to the latest vendor-provided versions
      owner: IT Operations
      due: 48h
      evidence: BSI vulnerability notification
updates:
  - at: "2026-08-26T01:01:08Z"
    level: L2
    summary: poc_available; added CVE-2024-28085; OS ubuntu 22.04
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SKYLER-FERRANTE-CVE-2024-28085&utm_source=rss&utm_medium=rss
---

The German Federal Office for Information Security (BSI) has reported the discovery of multiple vulnerabilities within the util-linux package, a collection of essential system utilities for Linux. These vulnerabilities are exploitable by a local attacker who already has access to the system. By leveraging these flaws, an unauthorized actor can achieve privilege escalation, bypass existing security controls, perform unauthorized data manipulation, or crash system services leading to a denial-of-service (DoS) state. Because util-linux provides core components such as mount, umount, fdisk, and chsh, these vulnerabilities represent a significant risk to the integrity and availability of Linux-based infrastructure. Administrators are advised to apply security patches provided by their respective Linux distributions as soon as they become available to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities allows local users to gain administrative privileges or disrupt system operations. This impact is critical for multi-user environments, cloud infrastructure, or shared hosting services where local access is provided to potentially untrusted users. If exploited, an attacker could move laterally or establish persistence with root access, leading to a complete compromise of the affected host.

## Recommendation

- Identify all systems running the affected version of util-linux using package management inventory logs (e.g., 'rpm -qa' or 'dpkg -l').
- Monitor vendor security repositories for patches and update util-linux across all production environments immediately upon release.
- Implement strict local access control policies and monitor for anomalous privilege escalation attempts on multi-user systems.
