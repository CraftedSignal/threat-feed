---
title: SSRF Vulnerability in Swarms library
slug: 2026-07-swarms-ssrf
description: The Swarms library contains a server-side request forgery (SSRF) vulnerability in the _is_safe_url function that allows attackers to bypass blocklists and access restricted internal services.
date: "2026-07-30T15:33:35Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - kyegomez
products:
  - Swarms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Swarms... contains a server-side request forgery vulnerability in the _is_safe_url function that fails to validate hostnames through DNS resolution, allowing attackers to bypass the blocklist.
    confidence_band: high
cves:
  - id: CVE-2026-67346
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67346
  - https://github.com/kyegomez/swarms/commit/8b0fc9e4645603ad94d5fcf4da86e3b9c71f4743
  - https://www.vulncheck.com/advisories/swarms-server-side-request-forgery-via-dns-rebinding-bypass
---

The Swarms library, in versions through 6.8.1, contains a server-side request forgery (SSRF) vulnerability due to improper hostname validation within the _is_safe_url function. The function fails to validate hostnames after DNS resolution, enabling an attacker to bypass intended blocklists. By submitting user-controlled URLs - specifically for image or audio processing - an attacker can trick the application into performing requests to private IP addresses, loopback addresses, or sensitive cloud metadata services. This vulnerability, identified as CVE-2026-67346, poses a high risk as it allows for unauthorized access to internal services, potentially leading to the exfiltration of credentials or sensitive environment data. The issue was addressed in commit 8b0fc9e.

## Impact

Successful exploitation allows unauthenticated attackers to interact with internal network resources that are otherwise unreachable from the public internet. This can result in unauthorized access to sensitive internal services, exfiltration of cloud metadata (such as IAM role credentials in AWS or GCP environments), and potential compromise of the host environment depending on the sensitivity of reachable internal endpoints.

## Recommendation

- Update the Swarms library to a version containing the fix from commit 8b0fc9e immediately.
- Implement strict egress filtering on servers running the library to prevent unauthorized requests to internal infrastructure or private metadata services (e.g., 169.254.169.254).
- Use network segmentation to isolate applications that handle user-supplied URLs from critical internal services.
- Monitor webserver logs for unexpected outbound requests originating from the application server context.
