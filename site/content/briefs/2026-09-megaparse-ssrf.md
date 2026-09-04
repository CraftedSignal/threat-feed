---
title: Unauthenticated SSRF in MegaParse
slug: 2026-09-megaparse-ssrf
description: MegaParse version 0.0.55 contains an unauthenticated server-side request forgery vulnerability in the POST /v1/url endpoint, allowing attackers to access internal resources and cloud metadata.
date: "2026-09-04T15:31:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:megaparse:megaparse:0.0.55:*:*:*:*:*:*:*
vendors:
  - MegaParse
products:
  - MegaParse (0.0.55)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MegaParse 0.0.55 contains an unauthenticated server-side request forgery vulnerability in the POST /v1/url endpoint.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can supply internal service URLs or metadata endpoints without authentication to read their responses.
    confidence_band: high
cves:
  - id: CVE-2026-85691
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85691
rules:
  - title: Detects CVE-2026-85691 Exploitation - Unauthenticated SSRF via /v1/url
    description: Detects exploitation of CVE-2026-85691 where the /v1/url endpoint is used to query internal cloud metadata or private IP ranges.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade MegaParse to a patched version
      owner: IT Operations
      due: 48h
      evidence: Source identifies CVE-2026-85691 in version 0.0.55
  hunt_leads:
    - lead: Search logs for POST /v1/url requests containing internal IP addresses
      technique_id: T1190
      data_needed:
        - Web application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit targets /v1/url endpoint with internal-facing URLs
  mitigation_plan:
    - priority: immediate
      action: Implement network egress filtering to prevent internal network scanning via MegaParse
      owner: IT Operations
      addresses: CVE-2026-85691
      evidence: Vulnerability allows arbitrary internal resource access
---

MegaParse version 0.0.55 contains a critical server-side request forgery (SSRF) vulnerability in the POST /v1/url endpoint. The application insecurely handles caller-supplied URLs, allowing unauthenticated remote attackers to force the server to perform HTTP requests to arbitrary destinations. By providing internal network addresses or cloud provider metadata service endpoints (e.g., 169.254.169.254) as input, an attacker can bypass access controls and receive the content of those internal requests directly in the application's JSON response. This vulnerability poses a significant risk to organizations deploying MegaParse in cloud-native environments, as it facilitates sensitive data exfiltration, internal reconnaissance, and potential compromise of cloud identity roles.

## Impact

Successful exploitation allows unauthenticated attackers to read responses from internal services that are otherwise unreachable from the internet. In cloud environments, this may result in the exfiltration of IAM credentials or sensitive metadata, leading to privilege escalation or further lateral movement within the cloud infrastructure.

## Recommendation

- Update MegaParse to a version that addresses CVE-2026-85691 immediately.
- Implement egress filtering on the host running MegaParse to prevent connections to internal RFC1918 address space and cloud metadata services.
- Monitor web application logs for POST requests to /v1/url that contain suspicious or internal-only URLs in the request body.
