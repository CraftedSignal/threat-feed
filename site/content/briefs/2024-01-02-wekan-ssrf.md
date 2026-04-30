---
title: WeKan SSRF Vulnerability in Webhook Integration
slug: 2024-01-02-wekan-ssrf
description: WeKan before 8.35 is vulnerable to server-side request forgery (SSRF), allowing attackers with integration modification privileges to set webhook URLs to internal network addresses, leading to unauthorized HTTP POST requests and potential comment manipulation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - wekan
  - cve-2026-41455
vendors:
  - WeKan
products:
  - WeKan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41455
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41455
rules:
  - title: Detect Suspicious WeKan Webhook URLs
    description: Detects suspicious WeKan webhook URLs that point to internal IP addresses or private network ranges, indicative of potential SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeKan Webhook URL Modifications
    description: Detects modifications to the webhook URL parameter, potentially indicating an attempt to exploit the SSRF vulnerability.
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

WeKan, a popular open-source kanban board application, is susceptible to a server-side request forgery (SSRF) vulnerability in versions prior to 8.35. This flaw resides in the handling of webhook integration URLs, where insufficient validation allows attackers to specify arbitrary internal network addresses as webhook targets. An attacker with the ability to create or modify integrations within WeKan can exploit this vulnerability. By crafting a malicious webhook URL, they can force the WeKan server to issue HTTP POST requests to attacker-controlled internal targets, potentially exposing sensitive internal resources and data. This vulnerability can also be chained with another flaw to overwrite arbitrary comment text without authorization checks, increasing the potential for data manipulation and unauthorized access.

## Attack Chain

1. An attacker gains access to a WeKan account with privileges to create or modify integrations.
2. The attacker navigates to the webhook integration settings within a WeKan board.
3. The attacker enters a malicious URL pointing to an internal server (e.g., `http://internal.example.com/admin`) in the webhook URL field.
4. The attacker triggers an event on the WeKan board (e.g., creating a new card, moving a card).
5. The WeKan server, without proper validation, sends an HTTP POST request to the attacker-specified internal URL.
6. The internal server receives the request, potentially revealing sensitive information about the WeKan board and its contents.
7. The attacker exploits response handling to overwrite arbitrary comment text without authorization checks.
8. The attacker gains unauthorized access to internal resources or sensitive data through the SSRF vulnerability.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to potentially access internal network resources that are otherwise inaccessible from the outside. This could lead to the disclosure of sensitive information, such as internal application configurations, database credentials, or other confidential data. Furthermore, the ability to overwrite arbitrary comment text can be used to deface WeKan boards, spread misinformation, or disrupt normal operations. The CVSS v3.1 base score for this vulnerability is 8.5, indicating a high severity risk.

## Recommendation

*   Upgrade WeKan to version 8.35 or later to remediate CVE-2026-41455.
*   Implement network segmentation to limit the impact of potential SSRF attacks.
*   Deploy the Sigma rule `DetectSuspiciousWekanWebhookUrls` to identify attempts to exploit this vulnerability by monitoring for requests to internal IP addresses or unusual domains.
*   Enable web server logging for the WeKan instance to capture details of outgoing HTTP requests.
