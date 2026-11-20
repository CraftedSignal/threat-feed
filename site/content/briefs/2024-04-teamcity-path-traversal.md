---
brief_id: brief-2024-04-29-teamcity-path-traversal
event_id: brief-2024-04-29-teamcity-path-traversal
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:5e675402624dd347abd407da31ba6afbe23b537048b73ff9eb5021a4dcb7b217
    summary: exploited:true; KEV CVE-2024-27199
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: JetBrains TeamCity Relative Path Traversal Vulnerability (CVE-2024-27199)
slug: 2024-04-teamcity-path-traversal
description: A relative path traversal vulnerability in JetBrains TeamCity (CVE-2024-27199) could allow limited administrative actions and has been linked to ransomware attacks.
date: "2024-04-29T12:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-20T00:00:00Z"
  confidence: high
tags:
  - cve-2024-27199
  - path-traversal
  - ransomware
  - jetbrains
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-27199
    cvss: 7.3
    epss: 0.91355
    kev: true
    kev_status: "true"
  - id: CVE-2024-27198
    kev_status: unknown
references:
  - https://www.cve.org/CVERecord?id=CVE-2024-27199
  - https://www.jetbrains.com/privacy-security/issues-fixed/
  - https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27199
rules:
  - title: TeamCity Path Traversal Attempt
    description: Detects potential path traversal attempts in TeamCity web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: TeamCity Unauthorized Admin Action
    description: Detects attempts to access sensitive TeamCity admin URLs
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2024-27199
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2024-27199 is a relative path traversal vulnerability affecting JetBrains TeamCity, a continuous integration and deployment server. This vulnerability allows attackers to perform limited administrative actions by manipulating file paths. JetBrains released a patch for this vulnerability in version 2023.11.4. CISA has added CVE-2024-27199 to its Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild, including its use in ransomware attacks. The vulnerability poses a significant risk to organizations using TeamCity, potentially leading to unauthorized access, data breaches, and system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable TeamCity server exposed to the internet.
2.  The attacker crafts a malicious HTTP request containing a relative path traversal sequence (e.g., `../../`) within a URL parameter related to administrative functions.
3.  The TeamCity server processes the crafted request without proper sanitization of the file path.
4.  The relative path traversal allows the attacker to access or modify restricted files or directories outside the intended scope.
5.  The attacker leverages the ability to perform limited admin actions, potentially modifying user permissions or injecting malicious code.
6.  The attacker escalates privileges, gaining full control over the TeamCity server.
7.  The attacker deploys ransomware to connected systems, encrypting data and demanding a ransom for its release.

## Impact

Successful exploitation of CVE-2024-27199 can lead to complete compromise of the TeamCity server and connected build agents. Due to TeamCity's central role in software development and deployment pipelines, this can lead to significant disruption, data loss, and potential supply chain attacks. The vulnerability has been linked to ransomware attacks, causing financial losses, reputational damage, and operational downtime for affected organizations.

## Recommendation

*   Apply the vendor-supplied patch by upgrading to TeamCity version 2023.11.4 or later to remediate CVE-2024-27199 ([https://www.jetbrains.com/privacy-security/issues-fixed/](https://www.jetbrains.com/privacy-security/issues-fixed/)).
*   Deploy the Sigma rules provided in this brief to detect exploitation attempts against TeamCity servers.
*   Follow CISA's BOD 22-01 guidance for cloud services to ensure proper security configurations and monitoring are in place.
