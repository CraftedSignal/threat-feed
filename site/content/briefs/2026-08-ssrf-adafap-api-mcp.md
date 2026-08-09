---
title: SSRF Vulnerability in adafap api-mcp (CVE-2026-19374)
slug: 2026-08-ssrf-adafap-api-mcp
description: An unauthenticated remote server-side request forgery (SSRF) vulnerability in the 'customAxios' function of adafap api-mcp allows attackers to make unauthorized requests from the server environment.
date: "2026-08-09T23:49:04Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - adafap
products:
  - api-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument url leads to server-side request forgery.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The attack is possible to be carried out remotely and leads to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-19374
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19374
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Implement egress filtering on servers running api-mcp
      owner: IT Operations
      due: 24h
      evidence: SSRF vulnerability allows unauthorized requests from the server-side environment.
  mitigation_plan:
    - priority: immediate
      action: Validate and sanitize 'url' parameter in customAxios function
      owner: IT Operations
      addresses: CVE-2026-19374
      evidence: Vulnerability exists in customAxios function of app/api/proxy/route.ts
---

The adafap api-mcp component is susceptible to server-side request forgery (SSRF) via improper validation of the 'url' argument within the 'customAxios' function located in 'app/api/proxy/route.ts'. This vulnerability exists in versions up to the commit hash 92b9a5d04acfec165c7d4ef852496593aa87be06. Because the product follows a continuous, rolling-release delivery model, there are no defined version numbers to track for patching. An unauthenticated remote attacker can supply a malicious URL to the proxy endpoint, forcing the application to perform requests to internal services or external targets on behalf of the server. This can lead to unauthorized information disclosure or interaction with restricted internal infrastructure. As of the time of reporting, the maintainers have not issued a response or a patch for this finding.

## Impact

Successful exploitation allows remote attackers to perform SSRF, potentially gaining unauthorized access to internal resources, cloud metadata services, or auxiliary network infrastructure. The impact is elevated by the lack of input sanitization in the proxy function, which provides a direct vector for internal network scanning and data exfiltration from private endpoints.

## Recommendation

- Implement strict URL allowlisting or validation in 'app/api/proxy/route.ts' to ensure the 'url' argument passed to 'customAxios' corresponds to approved, non-sensitive domains.
- Apply network-level egress filtering on the server hosting the affected application to restrict outbound requests to only necessary and known-safe destinations.
- Review web access logs for requests to 'app/api/proxy/route.ts' where the 'url' parameter contains internal IP addresses (e.g., 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
- Monitor for anomalous outbound traffic from the affected service container or host to prevent exfiltration or internal probing.
