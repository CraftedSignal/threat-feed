---
title: Gradio Open Redirect and Server-Side Request Forgery (SSRF) Vulnerability (CVE-2026-59806)
slug: 2026-07-gradio-open-redirect-ssrf
description: Gradio versions before 6.20.0 contain an open redirect and server-side request forgery (SSRF) vulnerability, CVE-2026-59806, allowing attackers to redirect users or perform client-side SSRF by supplying unvalidated HTTP/HTTPS URLs to the `/gradio_api/file=` endpoint, potentially leading to the retrieval of sensitive credentials, such as EC2 IAM role credentials.
date: "2026-07-08T20:19:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - ssrf
  - open-redirect
  - credential-access
  - cloud
  - gradio
vendors:
  - Gradio-app
products:
  - Gradio < 6.20.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Gradio before 6.20.0 contains an open redirect and server-side request forgery vulnerability that allows attackers to redirect users to arbitrary URLs or perform client-side SSRF by supplying unvalidated HTTP/HTTPS URLs to the file_fetch() function in the /gradio_api/file= endpoint.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can craft a malicious FileData response targeting internal endpoints such as cloud metadata services to retrieve sensitive credentials including EC2 IAM role credentials.
    confidence_band: high
cves:
  - id: CVE-2026-59806
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59806
  - https://github.com/gradio-app/gradio/commit/1c5c53842df9c2750552d85c19a92e7e732cff3f
  - https://github.com/gradio-app/gradio/issues/13593
  - https://github.com/gradio-app/gradio/pull/13596
  - https://github.com/gradio-app/gradio/releases/tag/gradio%406.20.0
  - https://www.vulncheck.com/advisories/gradio-open-redirect-and-ssrf-via-gradio-api-file-endpoint
rules:
  - title: Detects CVE-2026-59806 Exploitation - Gradio SSRF via file_fetch()
    description: Detects exploitation attempts of CVE-2026-59806 where attackers use unvalidated URLs in Gradio's file_fetch() function via the /gradio_api/file= endpoint to target AWS EC2 metadata services or other internal resources, indicating Server-Side Request Forgery (SSRF).
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.006
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, CVE-2026-59806, affects Gradio installations prior to version 6.20.0, exposing them to both open redirect and server-side request forgery (SSRF) attacks. This flaw resides within the `file_fetch()` function, accessible via the `/gradio_api/file=` endpoint, which fails to properly validate user-supplied HTTP/HTTPS URLs. Threat actors can leverage this vulnerability to craft malicious requests that either redirect users to arbitrary external websites or compel the Gradio server to make requests to internal network resources. The most severe consequence of the SSRF aspect is the potential to target cloud metadata services, such as AWS EC2 instance metadata, enabling attackers to retrieve highly sensitive credentials like IAM role access keys. This access can then be used to escalate privileges, exfiltrate data, or deploy further malicious infrastructure within compromised cloud environments.

## Attack Chain

1. The attacker identifies a Gradio application running a version prior to 6.20.0, potentially through automated scanning or reconnaissance.
2. The attacker crafts a malicious HTTP GET or POST request targeting the `/gradio_api/file=` endpoint of the vulnerable Gradio application.
3. Within the request, the attacker includes a specially crafted `FileData` parameter containing an unvalidated HTTP or HTTPS URL as input to the `file_fetch()` function.
4. For an open redirect attack, the attacker supplies an arbitrary external URL (e.g., `https://malicious-site.com/phish`).
5. For an SSRF attack, the attacker supplies an internal endpoint URL (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`) to access cloud metadata services.
6. The vulnerable Gradio server processes the request, internally making an HTTP request to the attacker-supplied URL without sufficient validation.
7. If the SSRF is successful against a cloud metadata service, the server retrieves sensitive data, such as EC2 IAM role credentials.
8. The Gradio server then returns the response containing the sensitive credentials or redirection instruction to the attacker through the original `FileData` response, achieving credential theft or user redirection.

## Impact

Successful exploitation of CVE-2026-59806 can lead to significant compromise. In the case of an open redirect, users interacting with the Gradio application can be involuntarily redirected to malicious phishing sites, leading to credential harvesting or malware downloads. More critically, the SSRF capability allows attackers to bypass network segmentation and access internal services that are not directly exposed to the internet. This includes highly sensitive cloud metadata APIs (e.g., AWS EC2), which can yield temporary IAM credentials. Compromise of these credentials enables attackers to assume roles, gain access to cloud resources, exfiltrate data from cloud storage, modify cloud configurations, or launch further attacks within the cloud environment. The overall risk is a complete takeover of cloud instances and associated data.

## Recommendation

* Patch Gradio to version 6.20.0 or later immediately to remediate CVE-2026-59806 as specified in the references.
* Implement web application firewall (WAF) rules to detect and block suspicious requests to the `/gradio_api/file=` endpoint containing known cloud metadata service IP addresses or internal network ranges in URL parameters.
* Deploy the Sigma rule below to your SIEM solution to detect attempts to exploit CVE-2026-59806 via SSRF by monitoring webserver logs.
* Review network segmentation and apply strict egress filtering to prevent Gradio applications from initiating connections to internal cloud metadata services or other sensitive internal IP ranges.
