---
title: LimeSurvey Server-Side Request Forgery Vulnerability (CVE-2026-63107)
slug: 2026-07-limesurvey-ssrf
description: An authenticated attacker can exploit CVE-2026-63107, a server-side request forgery vulnerability in LimeSurvey versions through 6.17.10 and 7.0.4, by manipulating the HTTP Host header in the REST API survey template endpoint, allowing the server to issue arbitrary HTTP requests to internal networks and cloud metadata services, potentially leading to the extraction of sensitive credentials like IAM tokens.
date: "2026-07-20T19:21:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-application
  - vulnerability
  - credential-access
  - data-exfiltration
vendors:
  - LimeSurvey
products:
  - LimeSurvey through 6.17.10
  - LimeSurvey through 7.0.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LimeSurvey through 6.17.10 and 7.0.4 contains a server-side request forgery vulnerability in the REST API survey template endpoint that allows authenticated users to cause the server to issue arbitrary HTTP requests by supplying a manipulated Host header.
    confidence_band: high
cves:
  - id: CVE-2026-63107
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63107
rules:
  - title: Detect Possible LimeSurvey SSRF via Host Header Manipulation (CVE-2026-63107)
    description: Detects CVE-2026-63107 exploitation - attempts to trigger SSRF in LimeSurvey by sending a manipulated Host header to the REST API survey template endpoint, targeting internal IPs or cloud metadata services. This rule focuses on the incoming HTTP request that initiates the SSRF.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1526
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-63107 identifies a server-side request forgery (SSRF) vulnerability affecting LimeSurvey versions up to 6.17.10 and 7.0.4. This critical flaw resides within the REST API survey template endpoint, specifically due to the unsanitized use of the HTTP Host header in the `getTemplateData()` function. An authenticated attacker can exploit this vulnerability by supplying a specially crafted `Host` header within their request. This manipulation forces the LimeSurvey server to initiate arbitrary HTTP requests to targets specified by the attacker, effectively bypassing network segmentation. The primary risk involves unauthorized access to internal network services, querying cloud metadata endpoints (such as those used by AWS, Azure, or GCP), and consequently, the potential extraction of highly sensitive credentials like Identity and Access Management (IAM) tokens, leading to broader cloud resource compromise. This vulnerability is significant for organizations using affected LimeSurvey instances, especially those deployed in cloud environments or with access to sensitive internal networks.

## Attack Chain

1. **Initial Access**: The attacker gains authenticated access to a vulnerable LimeSurvey instance, either through compromised credentials, session hijacking, or by having a legitimate user account.
2. **Vulnerability Identification**: The attacker identifies the vulnerable REST API survey template endpoint within the LimeSurvey application, knowing the `getTemplateData()` function processes the `Host` header unsanitized.
3. **Craft Malicious Request**: The attacker crafts an HTTP request targeting the identified REST API endpoint (e.g., `/index.php/api/.../survey/template`). This request is designed to trigger the `getTemplateData()` function.
4. **Manipulate Host Header**: Within the crafted HTTP request, the attacker modifies the standard `Host` header value to point to an internal network IP address (e.g., `192.168.1.1`), a specific internal service, or a cloud metadata service IP (e.g., `169.254.169.254`).
5. **Server-Side Request Forgery (SSRF)**: Upon receiving the attacker's request, the LimeSurvey server processes it. Due to the vulnerability, the `getTemplateData()` function misuses the manipulated `Host` header to construct and perform an *outgoing* HTTP request to the attacker-specified internal or cloud resource.
6. **Internal Network and Cloud Metadata Access**: The server's outgoing request reaches the intended internal target. This could be an internal web application, a database, or a cloud instance metadata service.
7. **Information Disclosure**: The internal resource responds to the server's request. The vulnerable LimeSurvey function may then inadvertently process and return this response data to the attacker through the legitimate API endpoint, revealing sensitive information such as internal network configurations, system details, or cloud IAM tokens.
8. **Credential Exfiltration**: The attacker extracts the sensitive information, such as IAM tokens, from the server's response, enabling further lateral movement or privilege escalation within the cloud environment or internal network.

## Impact

Successful exploitation of CVE-2026-63107 allows an authenticated attacker to perform server-side request forgery, gaining unauthorized access to internal network resources and cloud infrastructure. This can lead to sensitive data exposure, including the theft of critical cloud Identity and Access Management (IAM) tokens, which grant full control over cloud resources. For organizations hosting LimeSurvey in cloud environments, this poses a severe risk of cloud account compromise, data exfiltration from storage buckets, or unauthorized access to other cloud services. For on-premise deployments, attackers can map internal networks, access administrative interfaces, or pivot to other systems, circumventing network perimeter controls. The specific number of victims is not yet publicly reported, but all organizations using affected LimeSurvey versions are at risk.

## Recommendation

* Patch CVE-2026-63107 immediately by upgrading LimeSurvey to a version beyond 6.17.10 or 7.0.4, as specified in the vendor advisory.
* Deploy the Sigma rule "Detect Possible LimeSurvey SSRF via Host Header Manipulation" to your SIEM to monitor for exploitation attempts of CVE-2026-63107.
* Enable comprehensive web server logging for the LimeSurvey application, specifically capturing `cs-method`, `cs-uri-stem`, `cs-host`, `cs-uri-query`, and `sc-status` fields, to aid in detecting and investigating suspicious requests.
* Implement egress filtering on the network perimeter of your LimeSurvey server to restrict outbound connections to only necessary and approved destinations, thereby limiting the effectiveness of any SSRF attempts.
