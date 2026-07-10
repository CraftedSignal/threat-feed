---
title: NetScaler ADC and Gateway Vulnerabilities Lead to Session Mixup
slug: 2024-06-07-netscaler-session-mixup
description: A race condition vulnerability in NetScaler ADC and Gateway (CVE-2026-3055 and CVE-2026-4368) could lead to user session mixup, potentially allowing unauthorized access to sensitive information.
date: "2024-06-07T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - netscaler
  - citrix
  - session-hijacking
  - vulnerability
vendors:
  - Citrix
  - NetScaler
products:
  - NetScaler ADC
  - NetScaler Gateway
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s26oq2/vulnerabilities_have_been_discovered_in_netscaler/
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300&amp;articleURL=NetScaler_ADC_and_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_3055_and_CVE_2026_4368
rules:
  - title: NetScaler Unusual Authentication Source IP
    description: Detects authentication attempts from previously unseen source IPs to NetScaler ADC/Gateway
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - netscaler
  - title: NetScaler Failed Login Followed by Successful Login from Different IP
    description: Detects failed login attempts followed by successful logins from a different IP address, potentially indicating session hijacking
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - authentication
      - netscaler
rules_count: 2
---

NetScaler ADC (formerly Citrix ADC) and NetScaler Gateway (formerly Citrix Gateway) are affected by security vulnerabilities, including a race condition that can result in user session mixup. The vulnerabilities, identified as CVE-2026-3055 and CVE-2026-4368, expose organizations to the risk of unauthorized access to user sessions and data. While the exact method of exploitation isn't detailed in the source, the potential for session hijacking makes timely patching critical. The vulnerability was published on 2026-03-24 according to the source material. Organizations using affected versions of NetScaler ADC and Gateway are urged to apply the necessary patches immediately to mitigate the risk of exploitation.

## Attack Chain

1. An unauthenticated attacker attempts to access a resource protected by NetScaler ADC/Gateway.
2. The attacker triggers a race condition in the session management code (CVE-2026-3055, CVE-2026-4368).
3. Due to the race condition, the attacker's session is incorrectly associated with another user's authenticated session.
4. NetScaler ADC/Gateway grants the attacker access to the resource as if they were the legitimate user.
5. The attacker gains unauthorized access to the legitimate user's resources and data.
6. The attacker may perform actions on behalf of the legitimate user, such as accessing sensitive information or modifying settings.
7. The attacker could potentially escalate privileges within the compromised session, depending on the permissions of the legitimate user.
8. The attacker maintains unauthorized access until the legitimate user's session expires or is terminated.

## Impact

Successful exploitation of these vulnerabilities could allow an attacker to hijack user sessions, gaining unauthorized access to sensitive data and resources. The impact could range from data breaches and financial loss to reputational damage and compliance violations. The number of affected organizations is currently unknown, but any organization using vulnerable versions of NetScaler ADC and NetScaler Gateway is at risk.

## Recommendation

*   Immediately patch NetScaler ADC and NetScaler Gateway to the versions specified in Citrix Security Bulletin CTX696300 to address CVE-2026-3055 and CVE-2026-4368.
*   Monitor NetScaler ADC/Gateway logs for any unusual session activity or authentication anomalies that may indicate exploitation of these vulnerabilities.
*   Implement multi-factor authentication to add an additional layer of security and reduce the risk of unauthorized access, even if a session is compromised.
