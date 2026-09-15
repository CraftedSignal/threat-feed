---
title: Multiple Vulnerabilities in Veeam Backup & Replication
slug: 2026-05-veeam-backup-replication-vulns
description: Multiple vulnerabilities in Veeam Backup & Replication prior to version 13.0.2.29 allow an attacker to cause privilege escalation and compromise data integrity.
date: "2026-05-27T14:32:56Z"
lastmod: "2026-09-15T19:35:24Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=33866016-83AB-5C3F-9F66-0BE9BAA881E0&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - privilege-escalation
  - data-integrity
vendors:
  - Veeam
products:
  - Veeam Backup & Replication (< 13.0.2.29)
  - Veeam Agent for Microsoft Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32996
    epss: 0.00154
  - id: CVE-2026-32997
    epss: 0.00514
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0652/
  - https://www.veeam.com/kb4852
  - https://www.cve.org/CVERecord?id=CVE-2026-32996
  - https://www.cve.org/CVERecord?id=CVE-2026-32997
  - https://sploitus.com/exploit?id=33866016-83AB-5C3F-9F66-0BE9BAA881E0&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-32996 Exploitation Attempt - Veeam Unauthorized Configuration Access
    description: Detects potential exploitation of CVE-2026-32996 through unauthorized access to Veeam configuration files.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect CVE-2026-32997 Exploitation Attempt - Veeam Backup Modification
    description: Detects potential exploitation of CVE-2026-32997 by monitoring for unauthorized modifications to Veeam backup job configurations.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
updates:
  - at: "2026-09-15T19:35:24Z"
    level: L2
    summary: poc_available; added CVE-2026-32996 +1; OS windows
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=33866016-83AB-5C3F-9F66-0BE9BAA881E0&utm_source=rss&utm_medium=rss
---

Multiple vulnerabilities have been discovered in Veeam Backup & Replication. These flaws can be exploited by an attacker to achieve privilege escalation and compromise the integrity of backed-up data. The vulnerabilities affect Veeam Backup & Replication versions prior to 13.0.2.29. Successful exploitation could allow unauthorized access to sensitive data and systems managed by Veeam. This poses a significant risk to organizations relying on Veeam for data protection and recovery. It is crucial to apply the necessary patches provided by Veeam to mitigate these risks. The identified vulnerabilities are tracked as CVE-2026-32996 and CVE-2026-32997.

## Attack Chain

1. An attacker gains initial access to a system with Veeam Backup & Replication installed.
2. The attacker exploits CVE-2026-32996 to achieve privilege escalation within the Veeam application.
3. Using elevated privileges, the attacker gains unauthorized access to Veeam configuration files.
4. The attacker modifies backup job settings, potentially excluding critical data or injecting malicious code into backups.
5. The attacker exploits CVE-2026-32997 to further compromise data integrity, potentially corrupting backup files.
6. The attacker leverages the compromised Veeam infrastructure to access sensitive data stored in backup repositories.
7. The attacker exfiltrates sensitive data or deploys malicious code to systems during restoration processes.

## Impact

Successful exploitation of these vulnerabilities could lead to a significant compromise of data integrity and confidentiality. An attacker could gain unauthorized access to sensitive data, modify or delete backups, and potentially use the compromised Veeam infrastructure to launch further attacks against the organization. The vulnerabilities affect Veeam Backup & Replication versions prior to 13.0.2.29, potentially impacting a large number of organizations relying on Veeam for data protection.

## Recommendation

*   Upgrade Veeam Backup & Replication to version 13.0.2.29 or later to address CVE-2026-32996 and CVE-2026-32997.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts.
*   Monitor Veeam Backup & Replication logs for suspicious activity related to configuration changes or unauthorized access, enabling the appropriate logging level in Veeam.
