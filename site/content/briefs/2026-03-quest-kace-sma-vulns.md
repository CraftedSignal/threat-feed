---
title: Critical Vulnerabilities in Quest KACE SMA Allow System Takeover
slug: 2026-03-quest-kace-sma-vulns
description: Multiple critical vulnerabilities in Quest KACE Systems Management Appliance (SMA), including authentication bypass and 2FA bypass, allow unauthenticated attackers to achieve system takeover and cause denial of service; active exploitation is reported.
date: "2026-03-21T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - quest-kace
  - vulnerability
  - authentication-bypass
  - 2fa-bypass
  - denial-of-service
  - sma
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-found-quest-kace-systems-management-appliance-patch
  - https://support.quest.com/kb/4379499/quest-response-to-kace-sma-vulnerabilities-cve-2025-32975-cve-2025-32976-cve-2025-32977-cve-2025-32978
  - https://seclists.org/fulldisclosure/2025/Jun/22
  - https://seclists.org/fulldisclosure/2025/Jun/23
  - https://seclists.org/fulldisclosure/2025/Jun/24
  - https://seclists.org/fulldisclosure/2025/Jun/25
  - https://arcticwolf.com/resources/blog/cve-2025-32975/
rules:
  - title: Detect Unauthenticated Access Attempts to KACE SMA
    description: Detects potential unauthenticated access attempts to KACE SMA by monitoring for specific HTTP requests that are typically associated with authenticated sessions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - kace_sma
  - title: Detect Suspicious File Uploads to KACE SMA
    description: Detects suspicious file uploads to the KACE SMA server, potentially indicating an attempt to exploit CVE-2025-32977.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - kace_sma
rules_count: 2
---

Quest KACE Systems Management Appliance (SMA) is an IT systems management solution used by organizations to manage and secure endpoints. In June 2025, multiple critical vulnerabilities were disclosed. These include CVE-2025-32975, an authentication bypass; CVE-2025-32976, a 2FA bypass; CVE-2025-32977, malicious backup upload; and CVE-2025-32978, license replacement leading to denial of service. The vulnerabilities were discovered during a third-party assessment. As of March 20, 2026, active exploitation has been reported, making immediate patching critical. Versions affected include KACE SMA versions 13.0.385, 13.1.81, 13.2.183, 14.0.341, and 14.1.101. Successful exploitation can lead to complete system compromise, impacting enterprise security and operations.

## Attack Chain

1.  **Unauthenticated Request (CVE-2025-32975):** An attacker sends a crafted request to the KACE SMA server, exploiting the improper authentication handling in the SSO mechanism.
2.  **Authentication Bypass:** The server fails to properly validate the request, allowing the attacker to bypass authentication and impersonate a legitimate user, gaining unauthorized access to the system.
3.  **2FA Bypass (CVE-2025-32976):** If the attacker has valid credentials, they exploit a logic flaw in the two-factor authentication implementation to bypass TOTP-based 2FA requirements.
4.  **Privilege Escalation:** Using the bypassed authentication, the attacker gains access to administrative privileges within the KACE SMA.
5.  **Malicious Backup Upload (CVE-2025-32977):** An unauthenticated attacker uploads a malicious backup file to the system, exploiting weaknesses in the cryptographic signature validation process.
6.  **System Compromise:** The malicious backup content is processed, compromising the system's integrity and potentially allowing the attacker to execute arbitrary code.
7.  **License Replacement (CVE-2025-32978):** The attacker uses a web interface intended for license renewal to replace valid system licenses with expired or trial licenses.
8.  **Denial of Service:** The replacement of valid licenses causes a denial of service, disrupting normal operations and preventing legitimate users from accessing the system.

## Impact

Successful exploitation of these vulnerabilities allows attackers to gain complete control over the KACE SMA, leading to the compromise of managed endpoints. The denial-of-service vulnerability disrupts IT operations. While the exact number of victims is unknown, the widespread use of KACE SMA across various sectors suggests a broad potential impact. Active exploitation reported as of March 2026 increases the urgency.

## Recommendation

*   Apply the patches released by Quest for KACE SMA versions 13.0.385, 13.1.81, 13.2.183, 14.0.341 (Patch 5), 14.1.101 (Patch 4) to remediate CVE-2025-32975, CVE-2025-32976, CVE-2025-32977, and CVE-2025-32978.
*   Upscale monitoring and detection capabilities to identify any related suspicious activity as recommended by CCB.
*   Implement the Sigma rule "Detect Unauthenticated Access Attempts to KACE SMA" to identify potential exploitation attempts targeting CVE-2025-32975.
*   Review web server logs for suspicious file uploads to detect potential exploitation of CVE-2025-32977.
