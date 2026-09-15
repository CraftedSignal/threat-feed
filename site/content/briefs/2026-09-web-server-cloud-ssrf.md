---
title: Detection of SSRF Attempts Targeting Cloud Metadata Services
slug: 2026-09-web-server-cloud-ssrf
description: This detection rule identifies server-side request forgery (SSRF) attempts targeting cloud instance metadata endpoints (IMDS) across multiple web server platforms to harvest cloud credentials.
date: "2026-09-15T06:56:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - cloud-security
  - credential-access
vendors:
  - Amazon
  - Google
  - Microsoft
products:
  - AWS EC2 Instance Metadata Service
  - Google Cloud Platform Metadata Server
  - Azure Instance Metadata Service
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A common attacker pattern is exploiting an SSRF vulnerability so the application fetches http://169.254.169.254/latest/meta-data/iam/security-credentials/ or equivalent GCP and Azure metadata routes, then reuses the returned role credentials against cloud APIs.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers exploit server-side request forgery (SSRF) vulnerabilities in web applications to reach link-local metadata services.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_web_server_cloud_imds_ssrf_request.toml
  - https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
rules:
  - title: Detect Web Server Cloud Metadata SSRF Request
    description: Detects HTTP requests to web servers whose URL or query string references cloud instance metadata endpoints or equivalent encoded variants.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided detection rule to monitor web server access logs.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 8670bf41-cb64-4d65-a0d6-78af17cf8f30
  hunt_leads:
    - lead: Search historical logs for successful (200 OK) responses to requests containing 169.254.169.254 or other metadata paths.
      technique_id: T1552.005
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers rely on successful responses to exfiltrate credentials.
  mitigation_plan:
    - priority: immediate
      action: Enable IMDSv2 and configure proper hop limits for all cloud instances.
      owner: IT Operations
      addresses: Cloud instance security
      evidence: General cloud security best practice to prevent credential exposure via SSRF.
---

Attackers frequently exploit server-side request forgery (SSRF) vulnerabilities in web applications to interact with cloud instance metadata services (IMDS). By forcing a web server to make requests to internal-only endpoints such as 169.254.169.254, attackers attempt to retrieve temporary security credentials, identity tokens, and system configuration details associated with the underlying instance role or managed identity. This intelligence highlights the need for robust monitoring of web server access logs for requests containing metadata-related patterns, encoded IP addresses, and specific API paths used by AWS, GCP, and Azure. Successful exploitation allows unauthorized access to cloud resources, privilege escalation, and potential lateral movement within the cloud environment. Defending against this requires identifying the targeted endpoint, verifying if the server responded successfully, and auditing downstream cloud logs for the suspicious use of retrieved credentials.

## Attack Chain

1. An attacker identifies a web application endpoint vulnerable to SSRF that accepts user-supplied URLs or query parameters.
2. The attacker crafts a request containing an encoded or direct reference to a cloud metadata service endpoint (e.g., 169.254.169.254).
3. The web server process parses the malicious input and initiates an outbound HTTP request to the internal cloud metadata service.
4. The cloud metadata service responds to the server with sensitive data, including IAM role credentials or instance identity tokens.
5. The web application receives the response and potentially echoes the data back to the attacker or stores it in a location accessible to them.
6. The attacker captures the returned security tokens or credentials.
7. The attacker uses the exfiltrated credentials to authenticate against cloud APIs, gaining unauthorized access to the victim's cloud infrastructure.

## Impact

If successful, an SSRF attack leads to the compromise of temporary instance-based credentials. This impact typically manifests as unauthorized access to cloud management consoles, data exfiltration from storage buckets, modification of cloud infrastructure, or the compromise of additional cloud services linked to the affected instance's identity.

## Recommendation

Prioritize the implementation of the provided detection logic to identify SSRF attempts against cloud metadata services.
- Deploy the Sigma rules below to your SIEM and tune for your environment to identify requests targeting known metadata IP ranges and paths.
- Use the investigation steps in the rule guidance to correlate detected hits with successful outbound connections from the web server process to internal cloud metadata addresses.
- Enforce IMDSv2 and hop limits on all cloud instances to mitigate the impact of SSRF and prevent unauthorized credential retrieval.
- Implement strict outbound allowlists at the application level to block access to link-local and metadata-specific destinations.
