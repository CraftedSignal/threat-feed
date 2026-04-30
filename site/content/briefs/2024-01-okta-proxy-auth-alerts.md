---
title: Okta Alerts Following Unusual Proxy Authentication
slug: 2024-01-okta-proxy-auth-alerts
description: Attackers use proxy infrastructure to mask their origin when using stolen Okta credentials, and this rule correlates the first occurrence of an Okta user session started via a proxy with subsequent Okta security alerts for the same user.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - identity
  - cloud
  - okta
  - initial-access
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy
  - https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security
  - https://www.elastic.co/security-labs/starter-guide-to-understanding-okta
  - https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
rules:
  - title: Okta Proxy Authentication Followed By High Severity Alert
    description: Detects Okta authentication events originating from a proxy, followed by a high-severity alert for the same user within 30 minutes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: Okta VPN Authentication Followed By Security Alert
    description: Detects Okta authentication events via VPN, followed by subsequent security alerts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Attackers frequently use proxy infrastructure (VPNs, Tor, residential proxies) to mask their origin when using stolen credentials. This behavior often triggers additional detection rules after the initial authentication. By correlating the first instance of Okta user authentication via a proxy with subsequent Okta security alerts for the same user, this rule aims to identify potentially compromised accounts. This correlation focuses on activity within a 30-minute window following the initial proxy authentication, helping to pinpoint users whose proxy-based authentication was followed by suspicious activity. The rule leverages Okta system logs and alerts to identify these patterns. This is important for defenders to quickly identify compromised accounts and prevent further damage.

## Attack Chain

1.  An attacker obtains valid Okta credentials through phishing, credential stuffing, or other means. (T1078)
2.  The attacker initiates an Okta user session from behind a proxy (VPN, Tor, etc.) to mask their origin.
3.  Okta classifies the connection as originating from a proxy.
4.  The user successfully authenticates and starts a session.
5.  Post-authentication, the attacker attempts to access sensitive applications or data. (T1078.004)
6.  The attacker's activity triggers an Okta security alert, such as unusual access patterns or MFA bypass attempts.
7.  The detection rule correlates the proxy authentication event with the subsequent security alert.
8.  Security team investigates and responds to the potential account compromise.

## Impact

A successful attack can lead to unauthorized access to sensitive data, privilege escalation, and lateral movement within the organization's cloud environment. Multiple alerts, coupled with proxy authentication, indicate a higher likelihood of account compromise. If successful, attackers could exfiltrate sensitive data, modify configurations, or disrupt services.

## Recommendation

*   Deploy the Sigma rule "Okta Alerts Following Unusual Proxy Authentication" to your SIEM and tune for your environment to detect suspicious activity after proxy authentication.
*   Investigate correlated security alerts triggered after proxy authentication events for affected users, as highlighted by the Sigma rule.
*   Monitor Okta system logs for authentication events originating from known malicious proxy IP addresses and block them at the network perimeter.
*   Review user's Okta activity for signs of account takeover (MFA changes, new devices, unusual app access) after proxy authentication.
*   Implement multi-factor authentication (MFA) to reduce the risk of account compromise via stolen credentials, as this attack relies on valid accounts.
