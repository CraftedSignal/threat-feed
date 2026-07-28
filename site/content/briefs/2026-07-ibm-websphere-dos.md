---
title: IBM WebSphere Application Server - Liberty Denial of Service via Uncontrolled Heap Allocation (CVE-2026-15057)
slug: 2026-07-ibm-websphere-dos
description: IBM WebSphere Application Server - Liberty versions 17.0.0.3 through 26.0.0.7 are vulnerable to a denial of service (DoS) due to uncontrolled heap allocation, allowing an unauthenticated attacker to exhaust server resources and disrupt legitimate services.
date: "2026-07-28T21:27:25Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - java-application-server
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty (17.0.0.3)
  - WebSphere Application Server - Liberty (26.0.0.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: IBM WebSphere Application Server - Liberty ... is vulnerable to a denial of service due to uncontrolled heap allocation.
    confidence_band: high
cves:
  - id: CVE-2026-15057
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15057
  - https://www.ibm.com/support/pages/node/7280126
---

IBM WebSphere Application Server - Liberty is susceptible to a high-severity denial of service vulnerability, identified as CVE-2026-15057. This flaw affects versions 17.0.0.3 through 26.0.0.7 and is caused by uncontrolled heap allocation. An unauthenticated remote attacker can exploit this vulnerability by sending specially crafted requests, leading to excessive memory consumption on the server. This can result in resource exhaustion, causing the application server to become unresponsive or crash, thereby disrupting legitimate services. The vulnerability's CVSS v3.1 base score is 7.5 (High), emphasizing the critical need for immediate patching for organizations utilizing the affected software versions.

## Attack Chain

1. **Target Identification**: An attacker identifies publicly accessible instances of IBM WebSphere Application Server - Liberty.
2. **Vulnerability Confirmation**: The attacker verifies the server's version and determines it falls within the vulnerable range (17.0.0.3 through 26.0.0.7).
3. **Request Crafting**: The attacker constructs specific HTTP requests designed to trigger the uncontrolled heap allocation mechanism within the vulnerable server.
4. **DoS Initiation**: A high volume of these specially crafted malicious requests are sent to the target WebSphere Liberty server.
5. **Resource Consumption**: Upon receiving these requests, the server's application logic continuously allocates memory on the heap without proper release or boundary checks.
6. **Memory Exhaustion**: The server's available memory resources are rapidly depleted due to the uncontrolled heap growth.
7. **Service Interruption**: The server becomes unresponsive, experiences severe performance degradation, or crashes, leading to a denial of service for all legitimate users and applications.

## Impact

Successful exploitation of CVE-2026-15057 leads to a complete denial of service for the affected IBM WebSphere Application Server - Liberty instance. This can result in severe business disruption, as critical applications and services hosted on the server become unavailable. Organizations may face reputational damage, financial losses due to service downtime, and potential breaches of service level agreements. The impact is primarily on availability, with no direct confidentiality or integrity compromise mentioned in the vulnerability details.

## Recommendation

* Immediately apply the patch or update provided by IBM for CVE-2026-15057 to all affected IBM WebSphere Application Server - Liberty instances. The IBM support page reference provides details: `https://www.ibm.com/support/pages/node/7280126`.
* Monitor system resource utilization (CPU, memory, heap usage) on your IBM WebSphere Application Server - Liberty instances for sudden and unexplained spikes.
* Implement rate limiting and traffic filtering at the network edge (firewall/WAF) to mitigate the impact of high-volume, potentially malicious requests targeting application servers.
