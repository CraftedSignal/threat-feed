---
title: ACL Analytics Arbitrary Code Execution Vulnerability (CVE-2018-25320)
slug: 2026-05-acl-analytics-rce
description: ACL Analytics versions 11.x through 13.0.0.579 contain an arbitrary code execution vulnerability (CVE-2018-25320) that allows attackers to execute arbitrary commands by leveraging the EXECUTE function, potentially leading to remote code execution with system privileges.
date: "2026-05-17T13:17:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code execution
  - vulnerability
  - acl analytics
vendors:
  - ACL
products:
  - ACL Analytics (11.x through 13.0.0.579)
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2018-25320
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25320
  - https://www.acl.com
  - https://www.acl.com/products/acl-analytics/
  - https://www.exploit-db.com/exploits/44281
  - https://www.vulncheck.com/advisories/acl-analytics-11-x-arbitrary-code-execution
rules:
  - title: Detect Suspicious Bitsadmin Usage for Download
    description: Detects suspicious usage of bitsadmin to download files, often used in malware deployment and exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Reverse Shell
    description: Detects PowerShell commands indicative of a reverse shell being established.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

ACL Analytics versions 11.x through 13.0.0.579 are susceptible to an arbitrary code execution vulnerability. This vulnerability, identified as CVE-2018-25320, stems from the EXECUTE function within the software. An attacker can exploit this flaw to inject and execute arbitrary commands on the targeted system. The attack involves leveraging the EXECUTE function to download and execute malicious PowerShell scripts using bitsadmin. Successful exploitation grants the attacker SYSTEM-level privileges, enabling them to establish reverse shells and gain complete control over the compromised system. This vulnerability poses a significant threat to organizations using affected versions of ACL Analytics, potentially resulting in data breaches, system compromise, and further malicious activities.

## Attack Chain

1.  The attacker identifies a vulnerable ACL Analytics instance running versions 11.x through 13.0.0.579.
2.  The attacker crafts a malicious command that leverages the EXECUTE function within ACL Analytics.
3.  The crafted command uses bitsadmin to download a malicious PowerShell script from a remote server.
4.  ACL Analytics executes the bitsadmin command, downloading the PowerShell script to the compromised system.
5.  The downloaded PowerShell script is then executed with SYSTEM privileges.
6.  The PowerShell script establishes a reverse shell connection to the attacker's controlled server.
7.  The attacker gains complete control over the compromised system with SYSTEM privileges.
8.  The attacker can perform various malicious activities, including data exfiltration, installing malware, or pivoting to other systems on the network.

## Impact

Successful exploitation of CVE-2018-25320 can lead to complete system compromise. An attacker with SYSTEM privileges can access sensitive data, install malware, and pivot to other systems within the organization's network. This can result in significant financial losses, reputational damage, and legal liabilities. The vulnerability affects all organizations using ACL Analytics versions 11.x through 13.0.0.579, potentially impacting a wide range of sectors that rely on this software for data analysis and compliance.

## Recommendation

*   Upgrade ACL Analytics to a patched version beyond 13.0.0.579 to remediate CVE-2018-25320.
*   Deploy the Sigma rule "Detect Suspicious Bitsadmin Usage for Download" to identify potential exploitation attempts using bitsadmin as described in the attack chain.
*   Monitor process creation events for PowerShell scripts being executed with SYSTEM privileges after a bitsadmin download, as this is a common indicator of compromise, activating the "Detect PowerShell Reverse Shell" Sigma rule.
*   Implement network monitoring to detect reverse shell connections originating from systems running ACL Analytics.
