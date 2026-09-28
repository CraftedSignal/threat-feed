---
title: Server-Side Request Forgery in Privoce VoceChat Server
slug: 2026-09-vocechat-ssrf
description: Privoce VoceChat Server versions up to 0.5.36 are vulnerable to server-side request forgery via the open_graphic_parse endpoint, allowing remote attackers to perform unauthorized outbound requests.
date: "2026-09-28T05:11:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:privoce:vocechat_server:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-application
  - vulnerability
vendors:
  - Privoce
products:
  - VoceChat Server (<= 0.5.36)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument url can lead to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-100893
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100893
rules:
  - title: Detect CVE-2026-100893 Exploitation - SSRF in VoceChat open_graphic_parse
    description: Detects potential exploitation of CVE-2026-100893 by monitoring for POST requests to the open_graphic_parse endpoint containing URL schemes pointing to internal network segments or local loopback addresses.
    platform: sigma
    severity: high
    tactics:
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
    - action: Review egress traffic from VoceChat server instances for internal network scanning
      owner: SOC
      due: 24h
      evidence: Source identifies SSRF vulnerability allowing unauthorized requests
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network connectivity for VoceChat server via host-based firewall
      owner: IT Operations
      addresses: CVE-2026-100893
      evidence: Source identifies server-side request forgery as the primary impact
---

Privoce VoceChat Server up to version 0.5.36 contains a server-side request forgery (SSRF) vulnerability. The flaw exists within the open_graph::fetch function located in the src/api/resource.rs file, which powers the open_graphic_parse endpoint. An unauthenticated remote attacker can manipulate the url argument processed by this function to force the server to initiate unauthorized HTTP requests to arbitrary internal or external destinations. This vulnerability has been publicly disclosed, and exploitation is possible. As the vendor has not provided a response or a patch for this issue, defenders must assume the risk of exploitation remains for all instances running version 0.5.36 or earlier.

## Impact

Successful exploitation allows a remote attacker to bypass network perimeter defenses by leveraging the server as a proxy. This can lead to unauthorized access to internal services not exposed to the internet, exfiltration of cloud metadata (if hosted in AWS/GCP/Azure environments), or reconnaissance of private network architecture. The vulnerability carries a CVSS v3.1 base score of 7.3, reflecting its potential for significant impact on service integrity and network confidentiality.

## Recommendation

- Implement network egress filtering on all servers running VoceChat to prevent unauthorized outbound requests to sensitive internal network ranges or non-essential external endpoints.
- Monitor web server access logs for anomalous requests to the open_graphic_parse endpoint, specifically looking for unusual URL parameter values or unexpected destination hostnames.
- Due to the lack of a vendor-provided patch, consider placing the VoceChat instance behind a Web Application Firewall (WAF) and configure rules to inspect and restrict the 'url' parameter passed to the open_graphic_parse endpoint.
- If the application functionality is not critical, disable the open_graphic_parse endpoint entirely.
