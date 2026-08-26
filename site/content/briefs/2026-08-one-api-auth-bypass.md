---
title: Authorization Bypass in one-api via Channel Pinning
slug: 2026-08-one-api-auth-bypass
description: An authorization flaw in one-api allows authenticated users to bypass role checks and per-group restrictions by manipulating channel ID parameters to access unauthorized upstream provider keys.
date: "2026-08-26T16:22:09Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - one-api
products:
  - one-api
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The route carrying that parameter sits behind token authentication only, so any account holding a valid API token reaches it.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: A low-privilege account can therefore pin any channel by incrementing an identifier, causing the server to make upstream requests bearing an operator-configured provider key the account was never granted.
    confidence_band: high
cves:
  - id: CVE-2026-81027
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81027
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch one-api instance to the version remediating CVE-2026-81027
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web access logs for API requests with channelid parameters where the requester lacks administrative permissions.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The path-parameter branch sets the selected-channel value from c.Param(channelid) with no role check.
  mitigation_plan:
    - priority: immediate
      action: Patch software
      owner: IT Operations
      addresses: CVE-2026-81027
      evidence: NVD report
---

The one-api service contains an authorization bypass vulnerability (CVE-2026-81027) within its channel-pinning logic in middleware/auth.go. The application provides two methods for specifying a channel: a suffix on the API key and a URL path parameter. While the API key suffix method properly validates the user's administrative status, the URL path-parameter branch fails to perform any role checks before processing the request. 

An attacker with a valid, low-privilege API token can manipulate the "channelid" parameter in the URL. The application then uses this identifier to load the corresponding channel's credentials without verifying if the caller is authorized to access that specific channel or group. Consequently, the server proxies requests to the upstream provider using the operator's configured keys, effectively bypassing security controls including per-group restrictions and model allowlists. This allows unauthorized access to service provider endpoints and potentially incurs costs or exposes sensitive configuration data.

## Impact

Successful exploitation allows low-privileged users to bypass access controls and interact with unauthorized upstream LLM providers or services using the organization's API keys. This can lead to unauthorized resource consumption, potential data exfiltration via third-party providers, and the circumvention of established cost-management and policy-based controls. The vulnerability affects the core authorization flow of the one-api platform.

## Recommendation

- Upgrade one-api to the version containing the fix for CVE-2026-81027 immediately.
- Review application logs for anomalous patterns in requests containing channel identifiers in the URI path.
- Monitor for requests where the user context does not align with the requested channel ID or administrative roles.
