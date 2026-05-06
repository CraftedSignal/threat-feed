---
title: MagicMirror² Unauthenticated SSRF Vulnerability
slug: 2024-01-09-magicmirror-ssrf
description: An unauthenticated Server-Side Request Forgery (SSRF) vulnerability in MagicMirror² allows remote attackers to force the server to perform arbitrary HTTP requests, exfiltrate environment variables, and potentially compromise cloud instances or internal networks.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - magicmirror
  - cve-2026-42281
vendors:
  - npm
products:
  - magicmirror (<= 2.35.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
references:
  - https://github.com/advisories/GHSA-ph6f-2cvq-79hq
rules:
  - title: Detect MagicMirror CORS Endpoint SSRF Attempt
    description: Detects attempts to exploit the MagicMirror² SSRF vulnerability by monitoring requests to the /cors endpoint targeting metadata services or internal IPs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MagicMirror Environment Variable Exfiltration
    description: Detects attempts to exfiltrate environment variables via the MagicMirror² /cors endpoint by monitoring for requests with specific patterns.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MagicMirror² version 2.35.0 and earlier is vulnerable to an unauthenticated Server-Side Request Forgery (SSRF) vulnerability in the `/cors` endpoint. This flaw enables remote attackers to manipulate the MagicMirror² server into initiating arbitrary HTTP requests to internal networks, cloud metadata services (AWS, GCP, Azure), and localhost services. The vulnerability is located in the `js/server_functions.js` file, specifically within the `cors()` function. Attackers can exploit this by sending a crafted GET request to the `/cors` endpoint with a malicious URL. The server expands environment variable placeholders within the URL before making the request, allowing exfiltration of sensitive information. This vulnerability poses a significant risk to cloud deployments and internal networks, potentially leading to full compromise of cloud instance credentials and access to internal resources.

## Attack Chain

1.  Attacker identifies a MagicMirror² instance exposed on a network (default port 8080).
2.  Attacker crafts a GET request to the `/cors` endpoint with a target URL pointing to a cloud metadata service (e.g., `http://169.254.169.254/latest/meta-data/`).
3.  The MagicMirror² server receives the request and, without authentication or validation, processes the URL.
4.  The `replaceSecretPlaceholder()` function expands any environment variable placeholders (e.g., `**SECRET_API_KEY**`) in the URL.
5.  The server uses the `fetch()` function to make an HTTP request to the target URL.
6.  The cloud metadata service (or internal service) responds to the MagicMirror² server.
7.  The MagicMirror² server forwards the full response, including sensitive data like IAM role credentials or internal service responses, back to the attacker.
8.  The attacker obtains sensitive information, potentially leading to full cloud instance compromise, internal network access, or secret exfiltration.

## Impact

Successful exploitation of this SSRF vulnerability can have severe consequences. Cloud deployments (AWS/GCP/Azure) are at risk of full compromise due to access to instance metadata, including IAM role credentials. This can allow attackers to move laterally within the cloud account. Internal networks become accessible to the attacker through the compromised MagicMirror² server, allowing for scanning and interaction with internal services. Sensitive information such as API keys, database credentials, and other configuration data stored as environment variables can be exfiltrated. This impacts anyone running MagicMirror² exposed to an untrusted network.

## Recommendation

*   Deploy the Sigma rule `Detect MagicMirror CORS Endpoint SSRF Attempt` to identify potential exploitation attempts by monitoring for requests to the `/cors` endpoint with URLs targeting metadata services or internal IPs.
*   Deploy the Sigma rule `Detect MagicMirror Environment Variable Exfiltration` to detect requests to the `/cors` endpoint attempting to exfiltrate environment variables.
*   Block access to the following IOC at the network level to prevent initial reconnaissance: `169.254.169.254` (AWS IMDSv1 metadata service).
*   Upgrade MagicMirror² to a version higher than 2.35.0 to patch CVE-2026-42281.
