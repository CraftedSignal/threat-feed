---
title: SSRF Vulnerability in python-utcp via HttpCommunicationProtocol
slug: 2026-09-python-utcp-ssrf
description: The python-utcp library versions before 1.1.4 contain a server-side request forgery vulnerability due to improper validation of HTTP redirects within the HttpCommunicationProtocol.call_tool method.
date: "2026-09-27T19:09:19Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - python-utcp (< 1.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: python-utcp versions before 1.1.4 contain a server-side request forgery vulnerability in HttpCommunicationProtocol.call_tool that validates the initial tool URL but follows HTTP redirects without re-validating the target.
    confidence_band: high
cves:
  - id: CVE-2026-101060
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101060
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade python-utcp to version 1.1.4 or later
      owner: IT Operations
      addresses: CVE-2026-101060
      evidence: python-utcp versions before 1.1.4 contain a server-side request forgery vulnerability
---

The python-utcp library, specifically versions prior to 1.1.4, is affected by a server-side request forgery (SSRF) vulnerability identified as CVE-2026-101060. The issue resides in the HttpCommunicationProtocol.call_tool method, which fails to re-validate the target URL when an HTTP redirect is encountered. An attacker who controls a tool endpoint can respond with a 302 redirect to an arbitrary URL. Because the library does not verify the destination post-redirect, the UTCP client will follow the redirect to internal resources, such as cloud metadata services (e.g., 169.254.169.254) or internal HTTP endpoints. The final response body is then returned to the attacker, potentially leading to unauthorized data exfiltration or sensitive configuration disclosure.

## Impact

Successful exploitation allows unauthenticated attackers to perform SSRF attacks, enabling access to internal network resources and cloud metadata services. This can result in the exfiltration of sensitive information, such as IAM credentials or internal configuration data, depending on the environment where the application is deployed.

## Recommendation

1. Upgrade the python-utcp library to version 1.1.4 or later immediately.
2. Implement outbound network egress filtering on all servers running python-utcp to prevent connections to sensitive ranges like 169.254.169.254.
3. Audit applications using the HttpCommunicationProtocol.call_tool method to identify if they handle untrusted user-supplied URLs.
