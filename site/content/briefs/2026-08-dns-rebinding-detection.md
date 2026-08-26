---
title: Detection of DNS Rebinding via Public-to-Private Resolution Patterns
slug: 2026-08-dns-rebinding-detection
description: Attackers leverage DNS rebinding to bypass security boundaries by causing a public domain to resolve to internal, loopback, or private IP addresses, enabling unauthorized access to protected internal services.
date: "2026-08-26T00:44:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - dns-security
  - network-monitoring
  - threat-detection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Identifies a client resolving the same public registered domain to both a public IP address and a private, loopback, link-local, unique-local IPv6, or shared address.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy DNS logging to track resolved IP addresses and TTL values
      owner: IT Operations
      due: 72h
      evidence: Required DNS telemetry for detecting rebinding patterns
  hunt_leads:
    - lead: Identify all instances of a single domain resolving to both public and private IP addresses within 5 minutes
      technique_id: T1189
      data_needed:
        - DNS transaction logs (Zeek or Packet Capture)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detection rule logic identifies this pattern as consistent with rebinding
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict Host header validation on internal web applications
      owner: Application Security
      addresses: T1189
      evidence: Mitigates the impact of successful rebinding attacks on internal services
---

DNS rebinding is an attack technique used to circumvent browser-based security controls, such as the Same-Origin Policy, by manipulating the DNS resolution process. An attacker-controlled, publicly registered domain is initially configured to resolve to an attacker-owned public IP address to establish trust or deliver malicious payloads. Subsequently, the DNS record is updated to resolve to an internal, private, loopback, or link-local address (RFC1918, etc.). When a victim's client - typically a browser - attempts to connect, the resolution shifts to the internal address, effectively allowing the attacker's code to interact with internal resources, probe services, or perform unauthorized actions as if it were operating from within the trusted network. This behavior is highly effective for pivoting through browsers or applications to reach services that assume they are only accessible to local users. Defenders must monitor for rapid shifts between public and private IP responses to prevent unauthorized internal service exploitation.

## Attack Chain

1. Attacker registers a public domain name and sets up an authoritative DNS server.
2. Attacker configures the domain to resolve to an attacker-controlled public IP address.
3. Victim's browser or application is lured to the attacker-controlled domain, typically via phishing or drive-by compromise.
4. The victim's client performs a DNS query for the attacker's domain and receives the public IP address.
5. The attacker updates the DNS record on the authoritative server to point to an internal or loopback address (e.g., 127.0.0.1 or 192.168.x.x).
6. The victim's client performs a subsequent DNS query or the original resolution's TTL expires, forcing a re-query.
7. The client receives the internal IP address and attempts to connect, bypassing browser security policies.
8. The internal service receives the request, potentially leaking sensitive data or allowing state modification due to the implied trust of a local origin.

## Impact

DNS rebinding allows attackers to perform unauthorized actions against internal services, bypass firewall perimeters, and exfiltrate data from protected internal network segments. By successfully rebinding a domain, an attacker can turn a victim's web browser into a proxy for internal scanning, service exploitation, or sensitive data retrieval. This impact is significant in environments relying on IP-based trust or lacking robust authentication for internal web-based services.

## Recommendation

- Deploy DNS telemetry monitoring to detect rapid public-to-private IP resolution transitions as defined in the detection criteria.
- Establish a baseline for split-horizon DNS, VPN, and service discovery traffic to tune out legitimate internal infrastructure naming conventions.
- Ensure that internal web-based services validate the 'Host' header to reject requests that do not match the expected internal hostname.
- Implement outbound DNS filtering to prevent clients from resolving arbitrary external domains if direct egress is not required for business operations.
- Validate that DNS sensor placement is positioned to see endpoint-to-resolver traffic rather than upstream recursive resolver activity to ensure client-specific attribution.
