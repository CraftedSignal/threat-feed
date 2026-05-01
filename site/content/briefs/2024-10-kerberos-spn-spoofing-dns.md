---
title: Potential Kerberos SPN Spoofing via Suspicious DNS Query
slug: 2024-10-kerberos-spn-spoofing-dns
description: Detects suspicious DNS queries containing a base64-encoded blob, indicating potential Kerberos coercion attacks and SPN spoofing via DNS to coerce authentication to attacker-controlled hosts, enabling Kerberos or NTLM relay attacks.
date: "2026-05-01T17:31:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kerberos
  - spn-spoofing
  - dns
  - windows
vendors:
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025.html
  - https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/
  - https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
  - https://github.com/CICADA8-Research/RemoteKrbRelay/blob/main/README.md
  - https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/excalimap/mindmap/ad/authenticated.md
rules:
  - title: Detect Kerberos SPN Spoofing DNS Query
    description: Detects DNS queries with a base64 encoded string commonly used in Kerberos SPN spoofing attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.003
    data_sources:
      - dns_query
      - windows
  - title: Detect Process Making Suspicious DNS Query for Kerberos Coercion
    description: Detects processes that make DNS queries containing the base64-encoded Kerberos coercion marker.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a specific pattern in DNS queries indicative of Kerberos SPN spoofing, a technique used to coerce systems into authenticating to attacker-controlled hosts. The pattern "UWhRCA...BAAAA" represents a marshaled CREDENTIAL_TARGET_INFORMATION structure. Attackers exploit this by crafting malicious DNS names to trick victim systems into requesting Kerberos tickets for legitimate services, often their own identity, but directed towards an attacker-controlled endpoint. This can lead to Kerberos relay or NTLM reflection/relay attacks, bypassing normal NTLM fallback mechanisms. The technique is associated with tools like RemoteKrbRelay and wspcoerce. This activity has been observed in various attacks targeting Windows environments where Kerberos authentication is prevalent. Defenders need to detect and mitigate this early stage of credential access.

## Attack Chain

1.  The attacker identifies a target Windows system within the network.
2.  The attacker sets up a malicious server to receive coerced authentication requests.
3.  The attacker crafts a malicious DNS query containing a base64-encoded blob "UWhRCA...BAAAA" representing a marshaled CREDENTIAL_TARGET_INFORMATION structure.
4.  The victim system, triggered by an external factor (e.g., RPC call, scheduled task, or web request), attempts to resolve the crafted DNS name.
5.  The malicious DNS query is sent to the DNS server, which resolves to the attacker's server.
6.  The victim system initiates a Kerberos authentication request to the attacker's server, believing it to be a legitimate service.
7.  The attacker's server relays the Kerberos ticket or uses NTLM reflection/relay techniques to gain unauthorized access.
8.  The attacker compromises the victim system or pivots to other systems within the network using the stolen credentials.

## Impact

Successful exploitation can lead to credential compromise, lateral movement, and domain takeover. Victims in Active Directory environments are particularly vulnerable. The impact includes unauthorized access to sensitive data, disruption of services, and potential ransomware deployment. If the coerced service has high privileges, the attacker can gain complete control over the compromised system or even the entire domain. Organizations using Kerberos authentication are at risk.

## Recommendation

*   Deploy the "Potential Kerberos SPN Spoofing via Suspicious DNS Query" rule to your SIEM and tune for your environment to detect malicious DNS queries.
*   Enable Sysmon Event ID 22 - DNS Query logging to provide the necessary data for detection.
*   Investigate and block any DNS queries resolving to external IPs that contain the "UWhRCA...BAAAA" pattern.
*   Monitor process creation events for processes initiating DNS queries containing the suspicious pattern, specifically looking for known coercion tools.
*   Implement network segmentation to limit the impact of lateral movement if a system is compromised.
*   Review and harden Kerberos configurations to prevent SPN spoofing and relay attacks.
