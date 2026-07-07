---
title: Splunk RCE via User XSLT Exploitation (CVE-2023-46214)
slug: 2026-07-splunk-rce-xslt
description: This brief identifies potential remote code execution (RCE) attempts targeting Splunk servers by exploiting CVE-2023-46214, a vulnerability related to user-supplied Extensible Stylesheet Language Transformations (XSLT) that allows attackers to execute arbitrary code leading to full system compromise.
date: "2026-07-03T13:39:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:splunk:cloud:*:*:*:*:*:*:*:*
  - cpe:2.3:a:splunk:splunk:*:*:*:*:enterprise:*:*:*
tags:
  - application
  - rce
  - splunk
  - vulnerability
vendors:
  - Splunk
products:
  - Splunk Enterprise < 9.0.7
  - Splunk Enterprise < 9.1.2
  - Splunk Cloud Platform < 9.0.2308
  - Splunk Cloud Platform < 9.1.2308
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The following analytic identifies potential remote code execution (RCE) attempts via user-supplied Extensible Stylesheet Language Transformations (XSLT) in Splunk versions 9.1.x.
    confidence_band: high
cves:
  - id: CVE-2023-46214
    cvss: 8
    epss: 0.89066
references:
  - https://advisory.splunk.com/advisories/SVD-2023-1104
rules:
  - title: Detects CVE-2023-46214 Exploitation — Splunk RCE via User XSLT
    description: Detects CVE-2023-46214 exploitation attempts or successful RCE via user-supplied XSLT within Splunk's internal UI logs, indicative of malicious URI patterns and potential command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - application
      - splunkd_ui
rules_count: 1
---

Attackers are targeting Splunk Enterprise and Splunk Cloud Platform instances by exploiting CVE-2023-46214, an issue related to the improper handling of user-supplied Extensible Stylesheet Language Transformations (XSLT). This vulnerability, affecting Splunk Enterprise versions prior to 9.0.7 and 9.1.2, and Splunk Cloud Platform versions prior to 9.0.2308 and 9.1.2308, allows an authenticated user to achieve remote code execution on the underlying Splunk server. The attack typically involves crafting a malicious XSLT payload and submitting it through an interface that processes user-controlled XSLT. Successful exploitation can grant threat actors full control over the Splunk instance, enabling unauthorized data access, system modification, and further lateral movement within the compromised network. Defenders should prioritize patching and monitoring for indicators of attempted exploitation in their `splunkd_ui` logs.

## Attack Chain

1.  **Initial Access / Account Compromise**: An attacker gains access to a valid Splunk user account or identifies a publicly accessible endpoint that processes user-supplied XSLT without proper sanitization.
2.  **Malicious XSLT Crafting**: The attacker develops a specialized XSLT file containing malicious code designed to exploit CVE-2023-46214, targeting the Splunk server's underlying operating system.
3.  **XSLT Submission**: The malicious XSLT payload is submitted to the vulnerable Splunk instance, typically through an API endpoint or UI feature that accepts XSLT definitions.
4.  **Vulnerability Trigger**: The Splunk instance attempts to process the user-supplied XSLT, which triggers the remote code execution vulnerability (CVE-2023-46214).
5.  **Code Execution**: The malicious XSLT causes the Splunk server to execute arbitrary commands under the privileges of the Splunk daemon.
6.  **Post-Exploitation Actions**: The attacker runs commands on the Splunk server, such as creating new user accounts, deploying backdoors, or executing reconnaissance tools.
7.  **Impact**: The attacker proceeds with objectives such as data exfiltration from Splunk indexes, system compromise, or using the Splunk server as a pivot point for lateral movement.

## Impact

Successful exploitation of CVE-2023-46214 leads to critical consequences for affected organizations. Attackers can achieve full system compromise of the Splunk server, gaining complete control over the application and the underlying host. This allows for unauthorized access to sensitive data stored within Splunk indexes, potentially exfiltrating proprietary information, customer data, or security logs. Furthermore, the compromised Splunk instance can be used as a beachhead for lateral movement across the network, enabling broader attacks and impacting multiple systems. The number of potential victims is significant, as Splunk is widely deployed across various sectors for security and operational intelligence.

## Recommendation

*   Immediately patch all Splunk Enterprise instances to versions 9.0.7 or later, or 9.1.2 or later, and Splunk Cloud Platform instances to versions 9.0.2308 or later, or 9.1.2308 or later to remediate CVE-2023-46214.
*   Deploy the provided Sigma rule to your SIEM to detect potential exploitation attempts against Splunk instances.
*   Review `splunkd_ui` logs for URIs containing `NO_BINARY_CHECK=1`, `input.path=*.xsl`, or `dispatch*.xsl` which could indicate ongoing or attempted exploitation of CVE-2023-46214.
*   Investigate any detections of the provided Sigma rule, paying close attention to the `clientip`, `useragent`, and `status` fields to determine the nature and source of the activity.
