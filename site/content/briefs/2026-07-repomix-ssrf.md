---
title: 'CVE-2026-59702: repomix Server-Side Request Forgery'
slug: 2026-07-repomix-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability, CVE-2026-59702, in repomix's POST /api/pack endpoint allows attackers to make arbitrary outbound requests, potentially leading to internal network reconnaissance, access to cloud metadata services, and local filesystem path enumeration.
date: "2026-07-08T16:23:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - server-side-request-forgery
  - ssrf
  - cve
  - webserver
  - unauthenticated
  - initial-access
  - discovery
products:
  - repomix
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a server-side request forgery vulnerability in the POST /api/pack endpoint that allows unauthenticated attackers to make arbitrary outbound requests.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: enabling attackers to access private network addresses
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: enabling attackers to access... local filesystem paths.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: enabling attackers to access... GCP metadata services
    confidence_band: high
cves:
  - id: CVE-2026-59702
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59702
rules:
  - title: Detects CVE-2026-59702 Exploitation - repomix SSRF Attempt
    description: Detects CVE-2026-59702 exploitation attempts against the repomix /api/pack endpoint by identifying specific URL schemes or internal/metadata service IP addresses in the query string, indicative of Server-Side Request Forgery.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1018
      - T1083
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-59702 identifies a critical server-side request forgery (SSRF) vulnerability within the `repomix` software, specifically affecting its `POST /api/pack` endpoint. This flaw enables unauthenticated attackers to supply arbitrary URLs using `http://`, `https://`, and `file://` schemes. These malformed URLs are then processed by an internal `git clone` function without sufficient validation, causing the server to initiate connections to attacker-specified internal or external resources. The vulnerability, rated with a CVSS v3.1 base score of 9.3, presents a significant risk to organizations using `repomix`. Successful exploitation can expose sensitive internal network configurations, cloud metadata (such as from GCP), or local filesystem paths, leading to data exfiltration or further compromise.

## Attack Chain

1. **Vulnerable Service Identification:** An attacker identifies a publicly accessible instance of `repomix` exposing the `/api/pack` endpoint.
2. **Malicious Request Crafting:** The attacker constructs a `POST` request to `/api/pack`, embedding a crafted URL as a parameter, such as `url=http://169.254.169.254/latest/meta-data/` or `url=file:///etc/passwd`.
3. **Lack of Validation:** The `repomix` application receives the request and, due to improper input validation, accepts the malicious URL.
4. **Internal Request Trigger:** The application's `git clone` function attempts to resolve and connect to the provided URL, initiating an arbitrary outbound request from the server's perspective.
5. **Information Disclosure/Access:** The server connects to the internal resource (e.g., a private IP address, a cloud metadata service, or a local file path).
6. **Data Exfiltration:** The attacker receives the response from the internal resource through the `repomix` application, gaining access to sensitive information like cloud credentials, internal service details, or configuration files.
7. **Pivoting:** The attacker uses the gathered information to map the internal network, discover additional vulnerabilities, or escalate privileges within the compromised environment.

## Impact

The impact of successful exploitation of CVE-2026-59702 is substantial, allowing unauthenticated attackers to perform extensive reconnaissance of internal network assets. This includes the ability to access sensitive cloud metadata services, such as those used by Google Cloud Platform (GCP), which can yield valuable credentials or configuration data. Furthermore, attackers can enumerate and potentially access local filesystem paths on the vulnerable server, leading to the exposure of configuration files, user data, or even arbitrary file read. This information disclosure can directly facilitate further compromise, data exfiltration, or lateral movement within an organization's infrastructure.

## Recommendation

* Immediately patch `repomix` to address CVE-2026-59702 as soon as a fix becomes available from the vendor.
* Deploy the Sigma rule "Detects CVE-2026-59702 Exploitation - repomix SSRF Attempt" to your SIEM and tune for your environment to identify suspicious `POST` requests.
* Enable comprehensive web server logging for `POST` request bodies and query parameters for any application exposing an `/api/pack` endpoint to capture potential exploitation attempts of this vulnerability.
