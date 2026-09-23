---
title: SSRF via IPv6-Transition Address Bypass in LightRAG
slug: 2026-09-lightrag-ssrf
description: LightRAG versions 1.5.4 and earlier are vulnerable to Server-Side Request Forgery (SSRF) because the markdown parser fails to sanitize IPv6-encoded internal IPv4 addresses, allowing access to internal services and cloud metadata.
date: "2026-09-23T01:55:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hkuds:lightrag:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - cve
vendors:
  - HKUDS
products:
  - LightRAG (<= 1.5.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A caller who can upload a markdown or textpack document can make the LightRAG server issue HTTP requests to internal-only addresses.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The guard check is evaluated on the raw resolved address and never decodes IPv6 transition wrappers that embed an internal IPv4.
    confidence_band: high
cves:
  - id: CVE-2026-85740
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-vv3m-f8x4-7377
  - https://github.com/HKUDS/LightRAG/pull/3426
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade LightRAG to version 1.5.5 or higher to address CVE-2026-85740.
      owner: IT Operations
      due: 48h
      evidence: Source advisory states 1.5.5 contains the fix for CVE-2026-85740.
  mitigation_plan:
    - priority: immediate
      action: Set environment variable NATIVE_MD_IMAGE_DOWNLOAD_ENABLED to False.
      owner: IT Operations
      addresses: CVE-2026-85740
      evidence: Source notes the feature is enabled by default via this environment variable.
---

LightRAG's native markdown image-download mechanism contains a flawed SSRF guard in `lightrag/parser/markdown/parser.py`. The `_validated_addresses()` function performs an `is_global` check on resolved IP addresses but fails to account for IPv6-transition wrappers (NAT64, IPv4-compatible, and 6to4) that encapsulate internal IPv4 addresses. On network segments utilizing NAT64/DNS64 routing, these transition addresses bypass the application-level validation because the Python `ipaddress` library classifies the wrapper itself as globally routable. An attacker with the ability to upload markdown or textpack documents can supply these specially crafted addresses to force the server to initiate HTTP requests against internal infrastructure, including loopback services, RFC1918 internal network segments, and cloud provider metadata endpoints (e.g., 169.254.169.254). This vulnerability (CVE-2026-85740) allows for the unauthorized retrieval of internal data, credentials, and configuration metadata from the hosting environment.

## Attack Chain

1. Attacker obtains valid authentication for the LightRAG instance (e.g., via `combined_auth`).
2. Attacker crafts a malicious markdown document embedding an image URL containing an IPv6-wrapped internal IPv4 address (e.g., `http://[64:ff9b::0a42:0002]/x.png` for `10.66.0.2`).
3. Attacker uploads the document to the LightRAG API or platform.
4. The application's native markdown engine triggers `_download()` to fetch the referenced external images.
5. The guard `_validated_addresses()` resolves the target host and performs an `is_global` check on the wrapper; the check returns true, allowing the connection.
6. The `_build_guarded_opener` initiates an outbound HTTP request to the NAT64 gateway.
7. The gateway translates the IPv6 address to the internal IPv4 target and delivers the request to the restricted service.
8. The application ingests the response body from the internal service, effectively exfiltrating the data to the attacker.

## Impact

Successful exploitation allows for unauthorized SSRF against internal resources. This enables attackers to exfiltrate internal system data, harvest sensitive instance metadata (such as IAM temporary credentials in cloud environments), and probe internal network services that were intended to be unreachable from the application server. The vulnerability is especially critical in IPv6-only or NAT64-enabled infrastructure environments.

## Recommendation

Prioritize upgrading to LightRAG 1.5.5 or later, which implements recursive decoding of transition wrappers and rejects internal destinations regardless of the IPv6 encoding used. In the interim, operators should explicitly set the `NATIVE_MD_IMAGE_ALLOWED_NON_PUBLIC_CIDRS` configuration to restrict permitted egress or disable the native markdown image download functionality (`NATIVE_MD_IMAGE_DOWNLOAD_ENABLED=False`) if it is not business-critical. Detection engineers should inspect web server and proxy logs for requests containing IPv6-literal addresses, particularly those within the `64:ff9b::/96` range, to identify potential exploitation attempts.
