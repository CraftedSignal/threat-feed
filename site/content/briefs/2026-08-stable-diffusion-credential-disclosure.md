---
title: Credential Disclosure in Stable Diffusion WebUI via /sdapi/v1/cmd-flags
slug: 2026-08-stable-diffusion-credential-disclosure
description: Stable Diffusion WebUI versions 1.10.1 and earlier contain a credential disclosure vulnerability allowing unauthenticated remote attackers to retrieve cleartext authentication credentials.
date: "2026-08-28T21:41:01Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:automatic1111:stable_diffusion_webui:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - credential-disclosure
  - web-api
vendors:
  - Automatic1111
products:
  - Stable Diffusion WebUI (<= 1.10.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Unauthenticated attackers can access this endpoint to retrieve configured usernames and passwords.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Stable Diffusion WebUI ... contains a credential disclosure vulnerability in the /sdapi/v1/cmd-flags endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-82288
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82288
rules:
  - title: Detect CVE-2026-82288 Exploitation - Unauthorized Access to cmd-flags Endpoint
    description: Detects unauthorized GET requests to the vulnerable /sdapi/v1/cmd-flags endpoint, which may indicate an attempt to harvest credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review perimeter firewall logs for traffic to the /sdapi/v1/cmd-flags endpoint
      owner: SOC
      due: 24h
      evidence: Endpoint documentation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Stable Diffusion WebUI to a patched version beyond 1.10.1
      owner: IT Operations
      addresses: CVE-2026-82288
      evidence: NVD vulnerability notice
---

Stable Diffusion WebUI versions through 1.10.1 contain a significant credential disclosure vulnerability located within the /sdapi/v1/cmd-flags endpoint. This endpoint, intended for administrative visibility, improperly exposes parsed command-line arguments to any unauthenticated user who sends a request to the API. Specifically, the response includes the gradio_auth and api_auth configuration parameters, which frequently contain usernames and passwords defined at startup to secure the application. An attacker with network access to the Stable Diffusion instance can exploit this flaw to bypass authentication controls, potentially gaining full control over the AI image generation interface. This represents a critical risk for deployments exposed to the internet or untrusted internal networks, as it allows for trivial credential harvesting without requiring prior access or interaction.

## Impact

Successful exploitation results in the exposure of administrative or user credentials, enabling unauthorized access to the application interface. This can lead to the unauthorized execution of compute-intensive image generation tasks, modification of system configurations, or exfiltration of sensitive generated content. Organizations hosting Stable Diffusion WebUI instances that rely on these authentication flags for basic access control are at risk of complete account takeover.

## Recommendation

1. Upgrade Stable Diffusion WebUI to a version post-1.10.1 that remediates this information disclosure.
2. Implement strict network-level access controls to ensure the web application and its API endpoints are not reachable from the public internet.
3. Deploy the webserver-level detection rule provided below to identify unauthorized scanning or direct requests to the vulnerable API path.
4. Rotate any credentials identified in the command-line arguments (gradio_auth and api_auth) if the system has been accessible to untrusted parties.
