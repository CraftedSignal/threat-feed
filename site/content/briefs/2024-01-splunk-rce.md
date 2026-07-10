---
title: Splunk Remote Code Execution Vulnerability (CVE-2026-20204)
slug: 2024-01-splunk-rce
description: A low-privileged user can achieve remote code execution in vulnerable Splunk Enterprise and Cloud Platform versions by uploading a malicious file to the `$SPLUNK_HOME/var/run/splunk/apptemp` directory.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - splunk
  - rce
  - cve-2026-20204
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Cloud Platform
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-20204
    cvss: 7.1
    epss: 0.03282
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20204
rules:
  - title: Suspicious File Creation in Splunk Apptemp Directory
    description: Detects the creation of executable files within the Splunk apptemp directory, which could indicate exploitation of CVE-2026-20204.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - file_event
      - linux
  - title: Splunk Apptemp Directory File Upload by Non-Admin User
    description: Detects file uploads to the Splunk apptemp directory by users without admin or power roles, potentially indicating exploitation attempts related to CVE-2026-20204.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-20204 is a remote code execution vulnerability affecting Splunk Enterprise versions below 10.2.1, 10.0.5, 9.4.10, and 9.3.11, and Splunk Cloud Platform versions below 10.4.2603.0, 10.3.2512.5, 10.2.2510.9, 10.1.2507.19, 10.0.2503.13, and 9.3.2411.127. This vulnerability allows a low-privileged user, without `admin` or `power` roles, to execute arbitrary code on the Splunk instance. The root cause is improper handling and insufficient isolation of temporary files within the `$SPLUNK_HOME/var/run/splunk/apptemp` directory, enabling a malicious actor to upload and execute a crafted file. Exploitation could lead to complete system compromise, data exfiltration, or disruption of Splunk services.

## Attack Chain

1. A low-privileged user authenticates to the Splunk web interface.
2. The user crafts a malicious file (e.g., a Python script or executable) designed to execute arbitrary code.
3. The user uploads the malicious file to the `$SPLUNK_HOME/var/run/splunk/apptemp` directory, potentially through a vulnerable endpoint or feature that permits file uploads.
4. Splunk's internal processes improperly handle the uploaded file due to insufficient validation or sanitization.
5. The uploaded file is executed within the context of the Splunk instance, leveraging the permissions of the Splunk user.
6. The attacker gains remote code execution, allowing them to execute commands on the underlying operating system.
7. The attacker establishes persistence by creating a scheduled task or modifying system files.
8. The attacker pivots to other systems on the network, leveraging the compromised Splunk instance as a foothold.

## Impact

Successful exploitation of CVE-2026-20204 allows a low-privileged user to gain full control over the Splunk instance. This could lead to sensitive data being exposed, including logs, configurations, and user credentials. Attackers could also use the compromised Splunk instance to launch attacks against other systems within the organization's network, potentially resulting in widespread damage and disruption. The vulnerability has a CVSS v3.1 base score of 7.1, indicating a high severity.

## Recommendation

*   Upgrade Splunk Enterprise to version 10.2.1, 10.0.5, 9.4.10, or 9.3.11 or later to patch CVE-2026-20204.
*   Upgrade Splunk Cloud Platform to version 10.4.2603.0, 10.3.2512.5, 10.2.2510.9, 10.1.2507.19, 10.0.2503.13, or 9.3.2411.127 or later to patch CVE-2026-20204.
*   Monitor file creation events within the `$SPLUNK_HOME/var/run/splunk/apptemp` directory for suspicious file names or content using the provided Sigma rules.
*   Implement strict access control policies to limit file upload capabilities and restrict access to the `$SPLUNK_HOME/var/run/splunk/apptemp` directory.
