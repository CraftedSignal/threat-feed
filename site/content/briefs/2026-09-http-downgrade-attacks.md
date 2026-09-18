---
title: Detection of Potential HTTP Downgrade Attacks
slug: 2026-09-http-downgrade-attacks
description: Attackers may force HTTP protocol downgrades from secure versions like HTTP/2 to legacy versions to exploit header parsing inconsistencies and facilitate request smuggling or cache poisoning.
date: "2026-09-18T19:10:59Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-application-attack
  - defense-evasion
  - network-security
vendors:
  - Apache
  - Nginx
  - Traefik
products:
  - Apache HTTP Server
  - Apache Tomcat
  - Nginx
  - Traefik
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An HTTP downgrade attack occurs when an attacker forces a connection via an older HTTP version, resulting in potentially less secure communication.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_potential_http_downgrade_attack.toml
rules:
  - title: Detect Potential HTTP Downgrade Attack
    description: Detects HTTP traffic that uses a different HTTP version than the one typically used in the environment, indicating a potential forced protocol downgrade.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.010
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Baseline current HTTP versions across public-facing web infrastructure
      owner: Detection Engineering
      due: 7d
      evidence: Detection relies on identifying version deviations from environmental baselines.
  hunt_leads:
    - lead: Identify requests with conflicting headers (Content-Length and Transfer-Encoding) combined with legacy HTTP versions
      technique_id: T1562.010
      data_needed:
        - Web server request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Review the downgraded requests for exploitation indicators such as simultaneous Content-Length and Transfer-Encoding headers.
  mitigation_plan:
    - priority: short_term
      action: Enable WAF rules to drop requests with conflicting Content-Length and Transfer-Encoding headers
      owner: IT Operations
      addresses: T1562.010
      evidence: Enable WAF rules to drop requests with both Content-Length and Transfer-Encoding.
---

HTTP downgrade attacks involve an attacker deliberately forcing a web client or server to negotiate a less secure protocol version, such as moving from HTTP/2 to HTTP/1.1 or HTTP/1.0. This technique is often employed as a precursor to more complex attacks, including HTTP request smuggling, cache bypass, or exploitation of legacy protocol vulnerabilities that are not present in modern HTTP/2 implementations. By stripping away protections enforced by newer protocol versions, attackers leverage header parsing discrepancies and inconsistent handling of chunked transfer encoding between proxies, load balancers, and backend servers. Defenders should monitor for protocol version anomalies relative to established environment baselines to identify deliberate downgrade attempts. This approach is effective against web infrastructure including Nginx, Apache HTTP Server, Apache Tomcat, and Traefik deployments.

## Impact

Successful exploitation can lead to unauthorized access, cache poisoning, cross-user content exposure, and bypass of edge security controls. While the attack itself is a method of defense evasion, the downstream impact includes data exfiltration and credential theft via smuggled requests.

## Recommendation

Detection engineering teams should baseline the standard HTTP version used for web services and alert on deviations.
- Implement monitoring for unexpected HTTP/1.0 or HTTP/1.1 usage on endpoints where HTTP/2 is mandatory.
- Enable WAF rules to drop requests containing simultaneous Content-Length and Transfer-Encoding headers, or requests containing mixed-case header duplicates.
- Configure web servers to explicitly require TLS and ALPN "h2" negotiation on port 443, and disable support for cleartext "h2c" or legacy HTTP/1.0 protocols where business requirements allow.
- Normalize headers at the edge to reject malformed or ambiguous requests before they reach backend systems.
