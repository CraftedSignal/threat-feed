---
title: Web Server Cloud Metadata SSRF Exploitation
slug: 2026-07-web-server-cloud-metadata-ssrf
description: Attackers are actively exploiting Server-Side Request Forgery (SSRF) vulnerabilities in public-facing web applications to access cloud instance metadata services, such as those on AWS, GCP, and Azure, to harvest temporary credentials and sensitive instance details.
date: "2026-07-03T15:30:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - cloud-security
  - web-exploitation
  - credential-access
  - initial-access
  - webserver
vendors:
  - Amazon
  - Google
  - Microsoft
  - Nginx
  - Apache Software Foundation
  - Traefik Labs
products:
  - AWS
  - Google Cloud Platform (GCP)
  - Microsoft Azure
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - IIS
  - Traefik
  - Zeek
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers exploit server-side request forgery (SSRF) vulnerabilities in web applications to reach link-local metadata services on AWS, GCP, Azure, and similar cloud providers.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers exploit server-side request forgery (SSRF) vulnerabilities in web applications to reach link-local metadata services on AWS, GCP, Azure, and similar cloud providers and harvest temporary credentials, tokens, or instance details.
    confidence_band: high
references:
  - https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_web_server_cloud_imds_ssrf_request.toml
iocs:
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 100.100.100.200
  - type: ip
    value: 169.254.170.2
  - type: domain
    value: metadata.google.internal
  - type: domain
    value: metadata.goog
  - type: ip
    value: ::ffff:169.254.169.254
  - type: ip
    value: ::ffff:a9fe:a9fe
ioc_counts:
  domain: 2
  ip: 5
rules:
  - title: Web Server Cloud Metadata SSRF Request
    description: Detects HTTP requests targeting web servers whose URL or query string contains cloud instance metadata endpoints or their encoded variants, indicating an SSRF attempt to harvest credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552
      - T1552.005
    data_sources:
      - webserver
rules_count: 1
---

This threat involves the exploitation of Server-Side Request Forgery (SSRF) vulnerabilities found in web applications hosted on various platforms, including Nginx, Apache, IIS, and Traefik. Attackers leverage these vulnerabilities to manipulate web servers into making outbound requests to internal cloud instance metadata service (IMDS) endpoints. Such endpoints are typically associated with cloud providers like Amazon Web Services (AWS), Google Cloud Platform (GCP), and Microsoft Azure, and are used to provision temporary credentials, tokens, and instance-specific information. The objective is to steal these credentials, enabling unauthorized access and control over cloud resources, which can lead to data exfiltration, resource manipulation, or further lateral movement within the cloud environment. This technique is a well-known method for escalating privileges in compromised cloud workloads.

## Attack Chain

1.  **Initial Access via SSRF Vulnerability**: An attacker identifies and exploits a Server-Side Request Forgery (SSRF) vulnerability within a public-facing web application, which could be running on Nginx, Apache, IIS, or Traefik.
2.  **Internal Request Injection**: The attacker crafts a malicious HTTP request, embedding an internal cloud instance metadata service (IMDS) endpoint (e.g., `http://169.254.169.254/latest/meta-data/`) within a user-controlled URL or query parameter.
3.  **Web Server Initiates Internal Connection**: The vulnerable web application processes the malicious request and, due to the SSRF flaw, makes an outbound HTTP connection to the specified internal IMDS endpoint as if it were a legitimate internal service request.
4.  **Metadata Service Response**: The cloud instance metadata service responds to the web server's request, providing sensitive information such as temporary IAM role credentials (e.g., `meta-data/iam/security-credentials`), API tokens (e.g., `latest/api/token`), or instance configuration details.
5.  **Credential Exfiltration**: The web application receives the sensitive metadata or credentials and, depending on the SSRF exploit, leaks this information back to the attacker as part of the HTTP response or through other channels.
6.  **Cloud Resource Compromise**: The attacker uses the stolen temporary credentials to authenticate to the cloud provider's APIs (e.g., AWS CLI, GCP SDK), gaining unauthorized access to cloud resources, potentially leading to data exfiltration, privilege escalation, or further attacks.

## Impact

A successful SSRF attack against cloud instance metadata services can lead to significant compromise of cloud environments. Attackers can steal temporary credentials associated with the compromised workload, gaining unauthorized access to critical cloud resources, sensitive data, and the ability to manipulate cloud configurations. This can result in data breaches, resource hijacking, disruption of services, and the establishment of persistent access within the victim's cloud infrastructure. The breadth of potential impact depends on the permissions granted to the compromised instance's role or service account, which often include access to databases, object storage, and other core services.

## Recommendation

*   Deploy the Sigma rule "Web Server Cloud Metadata SSRF Request" to your SIEM to detect inbound HTTP requests containing cloud metadata endpoints.
*   Block the C2 domains and IP addresses listed in the IOC table at the network perimeter (firewall/WAF) to prevent outbound connections to known metadata services from unauthorized sources.
*   Implement strict outbound access controls and allowlisting at the network and application layer to restrict web applications from initiating connections to link-local addresses (e.g., 169.254.169.254) and other internal network ranges.
*   Enforce the use of IMDSv2 (Instance Metadata Service Version 2) on AWS EC2 instances, and similar authenticated access mechanisms for other cloud providers, to require session tokens for metadata access.
*   Regularly review and audit the permissions of cloud instance roles and managed identities, adhering to the principle of least privilege to minimize the impact of credential compromise.
