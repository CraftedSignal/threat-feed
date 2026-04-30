---
title: Red Hat Quay Deserialization Vulnerability Leads to Remote Code Execution (CVE-2026-32590)
slug: 2026-04-redhat-quay-rce
description: CVE-2026-32590 describes a deserialization vulnerability in Red Hat Quay's handling of resumable container image layer uploads, potentially allowing an attacker to execute arbitrary code on the Quay server by tampering with intermediate data stored in the database.
date: "2026-04-08T18:25:59Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-32590
  - redhat-quay
  - deserialization
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-32590
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32590
  - https://access.redhat.com/security/cve/CVE-2026-32590
  - https://bugzilla.redhat.com/show_bug.cgi?id=2446964
rules:
  - title: Detect Quay Deserialization Attempt
    description: Detects potential exploitation attempts of the Red Hat Quay deserialization vulnerability (CVE-2026-32590) by monitoring for suspicious processes spawned by the Quay server.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Quay Database Tampering
    description: Detects potential database tampering related to CVE-2026-32590 by monitoring for unauthorized access attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - database
      - linux
rules_count: 2
---

Red Hat Quay is vulnerable to a critical deserialization flaw, identified as CVE-2026-32590. This vulnerability resides in the handling of resumable container image layer uploads. Specifically, the way Quay stores intermediate data in its database during the upload process is susceptible to tampering. An attacker with the ability to manipulate this stored data can leverage this vulnerability to inject malicious serialized objects. When Quay attempts to deserialize this tampered data, it leads to arbitrary code execution within the Quay server's context. This poses a significant risk to the integrity and confidentiality of the container registry. The vulnerability was reported on April 8, 2026, and affects deployments of Red Hat Quay that have not been patched. Successful exploitation allows attackers to gain full control over the Quay server, potentially leading to data breaches, service disruption, and supply chain compromise.

## Attack Chain

1.  The attacker gains access to the Quay server's database or the mechanism used to store intermediate data during resumable uploads, potentially through SQL injection or other database vulnerabilities.
2.  The attacker intercepts a container image layer upload request to the Quay server.
3.  The attacker crafts a malicious payload containing a serialized object designed to execute arbitrary code upon deserialization.
4.  The attacker injects the malicious payload into the intermediate data stored in the database associated with the targeted resumable upload.
5.  The Quay server, during the process of resuming the upload, retrieves the tampered intermediate data from the database.
6.  The Quay server attempts to deserialize the data, triggering the execution of the malicious code embedded within the crafted serialized object.
7.  The attacker achieves arbitrary code execution on the Quay server with the privileges of the Quay application.
8.  The attacker leverages the gained access to compromise the entire Quay registry, potentially exfiltrating sensitive data, injecting malicious images, or disrupting the service.

## Impact

Successful exploitation of CVE-2026-32590 allows for arbitrary code execution on the Red Hat Quay server. This can lead to a complete compromise of the container registry, potentially affecting all container images stored within. Depending on the Quay server's configuration and connected systems, this could lead to further lateral movement within the network and compromise of other critical infrastructure. The severity is rated as HIGH with a CVSS score of 7.1, indicating a significant risk. If exploited, organizations could face data breaches, supply chain attacks through compromised container images, and prolonged service outages.

## Recommendation

*   Apply the patch or upgrade to a fixed version of Red Hat Quay as recommended by Red Hat to address CVE-2026-32590.
*   Implement database access controls to restrict unauthorized access and modification of the Quay database to prevent tampering with intermediate data.
*   Deploy a Web Application Firewall (WAF) to inspect and filter potentially malicious payloads in container image layer upload requests to mitigate exploitation attempts.
*   Enable robust logging and monitoring of database access and deserialization operations within the Quay server to detect suspicious activities related to this vulnerability.
*   Implement the provided Sigma rule `Detect Quay Deserialization Attempt` to identify potential exploitation attempts based on process execution and network connections.
