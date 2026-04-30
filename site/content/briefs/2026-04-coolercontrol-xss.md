---
title: CoolerControl-UI Stored XSS Vulnerability (CVE-2026-5301)
slug: 2026-04-coolercontrol-xss
description: Unauthenticated attackers can perform a stored XSS attack against CoolerControl/coolercontrol-ui versions less than 4.0.0 by injecting malicious JavaScript into log entries, leading to potential service takeover.
date: "2026-04-08T13:16:43Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - xss
  - cve-2026-5301
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5301
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5301
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/2.0.0/coolercontrol-ui/src/views/AppInfoView.vue?ref_type=tags#L224
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/3.1.1/coolercontrol-ui/src/views/AppInfoView.vue?ref_type=tags#L350
  - https://gitlab.com/coolercontrol/coolercontrol/-/releases/4.0.0
rules:
  - title: Detect Potential XSS in CoolerControl-UI Logs
    description: Detects potential cross-site scripting (XSS) attempts in CoolerControl-UI log entries by looking for common JavaScript injection patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Script Tags in HTTP Response (CoolerControl-UI)
    description: Detects script tags in HTTP response bodies, potentially indicating an XSS vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CoolerControl/coolercontrol-ui versions prior to 4.0.0 are vulnerable to a stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-5301. This flaw resides in the log viewer component of the application. Unauthenticated attackers can exploit this vulnerability by injecting malicious JavaScript code into log entries. When a user views the log entries containing the malicious script, the script executes within their browser, potentially allowing the attacker to take over the CoolerControl service. The vulnerability was reported by GitLab Inc. and affects versions prior to the release of version 4.0.0. This is a high severity vulnerability because it allows unauthenticated attackers to perform actions as other users in the application.

## Attack Chain

1.  The attacker identifies a CoolerControl/coolercontrol-ui instance running a version prior to 4.0.0.
2.  The attacker crafts a malicious log entry containing JavaScript code designed to execute arbitrary actions within a user's session, such as stealing cookies or redirecting to a phishing site.
3.  The attacker injects this malicious log entry into the CoolerControl/coolercontrol-ui system. The method of injection is not specified in the source but could involve exploiting other vulnerabilities or misconfigurations in the system.
4.  A user, such as an administrator, accesses the log viewer within the CoolerControl/coolercontrol-ui interface.
5.  The log viewer renders the malicious log entry, causing the injected JavaScript code to execute in the user's browser.
6.  The attacker gains control of the user's session or performs other malicious actions, such as stealing credentials or injecting further malicious content into the application.
7.  The attacker uses the compromised session to potentially escalate privileges and gain complete control over the CoolerControl service.

## Impact

Successful exploitation of CVE-2026-5301 can lead to a complete compromise of the CoolerControl service. An attacker could gain unauthorized access to sensitive data, modify system configurations, or use the compromised system as a launchpad for further attacks. Given the nature of XSS vulnerabilities, impact is highly dependent on the privileges of the user whose session is compromised.

## Recommendation

*   Upgrade CoolerControl/coolercontrol-ui to version 4.0.0 or later to remediate CVE-2026-5301.
*   Implement input validation and output encoding on all log entries to prevent the injection of malicious scripts.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts by monitoring for script execution in the context of the CoolerControl/coolercontrol-ui web application.
