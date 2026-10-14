---
title: SSRF in Portkey AI Gateway
slug: 2026-10-portkey-ai-ssrf
description: Portkey AI Gateway versions 1.14.0 through 1.15.2 are vulnerable to unauthenticated SSRF via the x-portkey-custom-host header, allowing attackers to access internal loopback and Docker host services.
date: "2026-10-14T16:40:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:portkey_ai:ai_gateway:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - cloud
vendors:
  - Portkey AI
products:
  - AI Gateway (1.14.0-1.15.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Portkey AI Gateway 1.14.0 through 1.15.2 contains a server-side request forgery vulnerability that allows unauthenticated attackers to reach loopback and Docker host services.
    confidence_band: high
cves:
  - id: CVE-2026-110719
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110719
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Portkey AI Gateway to version 1.15.3 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110719 advisory indicates vulnerability in versions 1.14.0 through 1.15.2.
  hunt_leads:
    - lead: Search web access logs for HTTP requests containing the header 'x-portkey-custom-host' with values targeting 127.0.0.1, localhost, or internal docker gateway IPs.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states attackers use a crafted x-portkey-custom-host header to reach loopback and internal services.
  mitigation_plan:
    - priority: immediate
      action: Configure the TRUSTED_CUSTOM_HOSTS environment variable to explicitly define allowed hostnames.
      owner: IT Operations
      addresses: CVE-2026-110719
      evidence: Source notes that the vulnerability occurs when TRUSTED_CUSTOM_HOSTS is unset.
---

Portkey AI Gateway versions 1.14.0 through 1.15.2 contain a server-side request forgery (SSRF) vulnerability due to improper host validation logic within the `isValidCustomHost` function. When the `TRUSTED_CUSTOM_HOSTS` configuration variable is left unset, the application incorrectly trusts localhost-style hostnames. An unauthenticated attacker can exploit this flaw by sending a crafted HTTP request to a `/v1` endpoint, specifically utilizing the `x-portkey-custom-host` header. By targeting loopback addresses or internal Docker host services through this header, an attacker can coerce the gateway to perform unauthorized requests on their behalf and return the resulting data from internal services back to the attacker. This vulnerability poses a significant risk to the confidentiality and integrity of internal infrastructure that is otherwise not exposed to the public internet.

## Impact

Successful exploitation allows an unauthenticated attacker to interact with internal services that are only accessible from the loopback interface or within the Docker environment where the AI Gateway is hosted. This can lead to unauthorized information disclosure, interaction with internal management APIs, or potential secondary exploitation of internal microservices that assume all incoming requests are originating from trusted internal sources.

## Recommendation

- Upgrade Portkey AI Gateway to a version beyond 1.15.2 immediately.
- If upgrading is not immediately possible, explicitly configure the `TRUSTED_CUSTOM_HOSTS` environment variable to restrict the gateway to a strict allowlist of known-safe, non-internal hostnames.
- Audit access logs for requests containing the `x-portkey-custom-host` header to identify potential exploitation attempts directed at internal loopback (127.0.0.1) or private Docker host IP addresses.
