---
title: Potential HTTP Downgrade Attack Detected
slug: 2024-01-http-downgrade
description: The new_terms rule detects potential HTTP downgrade attacks by identifying HTTP traffic using a different HTTP version than typically used, potentially exposing systems to vulnerabilities in older protocols.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - http-downgrade
  - web-server
vendors:
  - Nginx
  - Apache
  - Traefik
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - Traefik
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_potential_http_downgrade_attack.toml
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/010/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: HTTP Downgrade Attack Detected via Version Mismatch
    description: Detects potential HTTP downgrade attacks by identifying HTTP traffic using an older HTTP version than expected.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.010
    data_sources:
      - network_connection
      - nginx|apache|apache_tomcat|traefik
  - title: Suspicious Header Combinations Indicative of HTTP Smuggling Attempt
    description: Detects requests with both Content-Length and Transfer-Encoding headers, which are often used in HTTP smuggling attacks after a downgrade.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.010
    data_sources:
      - network_connection
      - nginx|apache|apache_tomcat|traefik
rules_count: 2
---

This rule from Elastic detects potential HTTP downgrade attacks by identifying HTTP traffic that negotiates an older HTTP version than what is typically used in the environment. The rule leverages the `new_terms` rule type to identify unusual HTTP versions, such as HTTP/1.1 when HTTP/2 is expected. An attacker may force a downgrade to exploit vulnerabilities in older protocols, bypass security measures, or conduct request smuggling attacks. This rule is designed to work with web server access logs, specifically Nginx, Apache, Apache Tomcat, and Traefik. The rule is triggered when a new HTTP version is observed relative to the baseline.

## Attack Chain

1. An attacker identifies a target web server supporting HTTP/2.
2. The attacker sends a crafted HTTP request that disrupts HTTP/2 negotiation (e.g., by omitting ALPN).
3. The web server falls back to HTTP/1.1 or HTTP/1.0 due to the failed HTTP/2 negotiation.
4. The attacker crafts HTTP/1.1 requests with techniques like simultaneous Content-Length and Transfer-Encoding headers or mixed-case headers.
5. The attacker attempts request smuggling or cache poisoning by exploiting differences in how the web server and backend systems parse the downgraded HTTP requests.
6. The web server returns unexpected responses, such as 4xx or 5xx errors, or exhibits increased latency.
7. The attacker may gain unauthorized access to resources or compromise other users' sessions.

## Impact

Successful HTTP downgrade attacks can lead to various security issues. Attackers can exploit vulnerabilities specific to older HTTP versions, bypass security controls designed for newer protocols, or conduct request smuggling and cache poisoning attacks. This can lead to unauthorized access to sensitive information, denial of service, or other malicious activities. While the rule severity is low, successful exploitation after a downgrade can result in high impact.

## Recommendation

*   Deploy the Sigma rule "HTTP Downgrade Attack Detected via Version Mismatch" to your SIEM and tune based on your environment to detect potential downgrade attempts (see rule below).
*   Correlate detected downgrade events with other security logs, such as TLS termination or load balancer logs, to verify ALPN negotiation as described in the rule's note section.
*   Review server configurations to disable cleartext h2c and HTTP/1.0 on public endpoints, enforcing TLS+ALPN "h2" on port 443 as recommended in the rule's note section.
*   Implement WAF rules to drop requests with "Upgrade: h2c", simultaneous Content-Length and Transfer-Encoding headers, or duplicated/mixed-case headers to mitigate request smuggling attempts as recommended in the rule's note section.
