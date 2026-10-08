---
title: Denial-of-Service Vulnerability in IBM Guardium Data Protection
slug: 2026-10-ibm-guardium-dos
description: IBM Guardium Data Protection 12.2.2 is susceptible to an unauthenticated remote denial-of-service attack via malformed gRPC task data that causes the edge-controller process to crash.
date: "2026-10-08T19:40:20Z"
lastmod: "2026-10-08T22:11:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:guardium_data_protection:12.2.2:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - cve-2026-84276
  - xss
  - web-vulnerability
  - cve
  - ibm
  - network-security
  - privilege-escalation
vendors:
  - IBM
products:
  - Guardium Data Protection (12.2.2)
  - Guardium Data Protection (12.2)
  - Guardium Data Protection (12.1, 12.2.2)
  - Guardium Data Protection (12.0, 12.1, 12.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker with network access to the edge-controller gRPC service can provide malformed task data that triggers an unchecked type assertion, causing the edge-controller process to terminate unexpectedly.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker who can influence monitored database traffic could execute malicious script in the browser of an authenticated Guardium user.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An unauthenticated remote attacker could exploit this vulnerability to execute arbitrary container images.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low-privileged local user could exploit this vulnerability to gain root privileges and access or modify sensitive system files.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Password in Files or Arguments'
    evidence: IBM Guardium Data Protection 12.2 is vulnerable due to weak cryptographic protection and a hard-coded recovery key in the pkcrypto passkey component.
    confidence_band: high
cves:
  - id: CVE-2026-84276
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84276
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84244
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84272
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82334
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84245
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84250
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch IBM Guardium Data Protection 12.2.2 to the version resolving CVE-2026-84276.
updates:
  - at: "2026-10-08T22:01:22Z"
    level: L1
    summary: added coverage for Guardium Data Protection (12.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84244
  - at: "2026-10-08T22:02:11Z"
    level: L2
    summary: added coverage for Guardium Data Protection (12.1, 12.2.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84272
  - at: "2026-10-08T22:08:34Z"
    level: L2
    summary: added coverage for Guardium Data Protection (12.0, 12.1, 12.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82334
  - at: "2026-10-08T22:10:39Z"
    level: L2
    summary: added coverage for Guardium Data Protection (12.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84245
  - at: "2026-10-08T22:11:23Z"
    level: L2
    summary: added coverage for Guardium Data Protection (12.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84250
---

IBM Guardium Data Protection version 12.2.2 contains a high-severity denial-of-service (DoS) vulnerability identified as CVE-2026-84276. The vulnerability exists within the edge-controller component. An unauthenticated remote attacker with network connectivity to the edge-controller gRPC service can transmit specifically crafted, malformed task data to the application. Due to an unchecked type assertion within the code handling these gRPC requests, the edge-controller process encounters an unhandled exception and terminates unexpectedly. This disruption impacts the availability of the data protection services managed by the edge-controller. Defenders should monitor for unexpected restarts of the edge-controller process and restrict access to the gRPC service to known, trusted infrastructure.

## Impact

Successful exploitation of this vulnerability results in an immediate service disruption of the edge-controller component within IBM Guardium Data Protection 12.2.2. Organizations relying on this platform for sensitive data protection and monitoring will lose visibility and security enforcement during the period of service unavailability. This vulnerability is particularly critical for environments where the edge-controller is internet-exposed or reachable from untrusted network segments.

## Recommendation

Prioritize patching for all affected IBM Guardium Data Protection 12.2.2 installations to the version addressing CVE-2026-84276. In the interim, restrict network access to the gRPC service associated with the edge-controller to only trusted management subnets using network firewalls or ACLs. Audit infrastructure logs for repeated crash events or unexpected service restarts of the edge-controller process.
