---
title: Cisco Releases Security Advisories for Multiple Products
slug: 2026-05-cisco-multiple-vulns
description: Cisco released security advisories on May 6, 2026, addressing vulnerabilities including remote code execution, server-side request forgery, and denial of service in Crosswork Network Controller, IoT Field Network Director, Network Services Orchestrator, SG350/SG350X Managed Switches, and Unity Connection.
date: "2026-05-06T19:25:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cisco
  - vulnerability
  - denial-of-service
  - remote-code-execution
  - server-side-request-forgery
vendors:
  - Cisco
products:
  - Crosswork Network Controller (CNC)
  - IoT Field Network Director (FND)
  - Network Services Orchestrator (NSO)
  - SG350 Managed Switch
  - SG350X Managed Switch
  - Unity Connection
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0008
    tactic_name: Evasion
    technique_id: T1068
    technique_name: Exploit Vuln
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-430
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-unity-rce-ssrf-hENhuASy
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sg350-snmp-dos-GEFZr2Tj
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nso-dos-7Egqyc
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iot-fnd-dos-n8N26Q4u
  - https://tools.cisco.com/security/center/publicationListing.x
rules:
  - title: Cisco Unity Connection - Potential SSRF Attempt
    description: Detects potential Server-Side Request Forgery (SSRF) attempts against Cisco Unity Connection servers based on suspicious HTTP GET requests. This may indicate an attempt to exploit CVEs related to SSRF vulnerabilities in Cisco Unity Connection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Cisco SG350/SG350X - Excessive SNMP Requests
    description: Detects a potential Denial of Service attack against Cisco SG350/SG350X series managed switches by monitoring for a high volume of SNMP requests. This may indicate an attempt to exploit CVEs related to SNMP DoS vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Cisco NSO / CNC - Connection Exhaustion Attempt
    description: Detects a potential connection exhaustion DoS attack against Cisco NSO/CNC by monitoring for a high number of connections from a single source IP. This rule may indicate an attempt to exploit the connection exhaustion vulnerability mentioned in the advisory.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

On May 6, 2026, Cisco released multiple security advisories addressing vulnerabilities across several of their products. These advisories cover a range of issues, including remote code execution (RCE), server-side request forgery (SSRF), and denial-of-service (DoS) vulnerabilities. Affected products include Cisco Crosswork Network Controller (CNC) version 7.1 and prior, Cisco IoT Field Network Director (FND) version 4 and prior and versions prior to 5.0.0-117, Cisco Network Services Orchestrator (NSO) version 6.3 and prior and versions prior to 6.4.1.3, Cisco SG350 and SG350X Managed Switches (multiple versions and models), and Cisco Unity Connection versions prior to 12.5, 14SU5, and 15SU4. These vulnerabilities could allow attackers to disrupt services, gain unauthorized access, or execute arbitrary code. It is crucial for administrators to review and apply the necessary updates.

## Attack Chain

Since the advisory covers multiple vulnerabilities across different products, a generalized attack chain cannot be provided. However, the following represents a plausible attack chain for a denial-of-service vulnerability in a network management platform, extrapolating from the advisories' scope:

1.  The attacker identifies a vulnerable Cisco Crosswork Network Controller or IoT Field Network Director instance.
2.  The attacker sends a series of crafted network requests to the vulnerable server.
3.  The server improperly handles the requests, leading to excessive resource consumption.
4.  The server's CPU, memory, or network bandwidth becomes saturated.
5.  The server becomes unresponsive to legitimate requests.
6.  Network management operations are disrupted, impacting network stability.
7.  Administrators are unable to manage or monitor the network effectively.
8.  The denial-of-service condition persists until the malicious traffic is blocked or the server is restarted.

## Impact

Successful exploitation of these vulnerabilities can lead to denial of service, remote code execution, and unauthorized access. A denial-of-service condition on network management platforms like Crosswork Network Controller or IoT Field Network Director can disrupt network operations, preventing administrators from managing and monitoring the network effectively. Remote code execution on Cisco Unity Connection could allow attackers to gain complete control over the affected system. Server-Side Request Forgery can lead to internal information disclosure. The specific number of affected organizations is unknown, but given the widespread use of Cisco products, the potential impact is significant.

## Recommendation

*   Review the Cisco Security Advisories and identify the products in your environment that are affected. (Reference: Cisco Security Advisories Links)
*   Apply the recommended updates to Cisco Unity Connection to mitigate the Remote Code Execution and Server-Side Request Forgery vulnerabilities. (Reference: Cisco Unity Connection Advisory)
*   Apply the recommended updates to Cisco SG350 and SG350X Series Managed Switches to mitigate the SNMP Denial of Service Vulnerability. (Reference: Cisco SG350 and SG350X Series Managed Switches Advisory)
*   Apply the recommended updates to Cisco Crosswork Network Controller and Cisco Network Services Orchestrator to mitigate the Connection Exhaustion Denial of Service Vulnerability. (Reference: Cisco Crosswork Network Controller and Cisco Network Services Orchestrator Advisory)
*   Apply the recommended updates to Cisco IoT Field Network Director to mitigate the identified vulnerabilities. (Reference: Cisco IoT Field Network Director Advisory)
