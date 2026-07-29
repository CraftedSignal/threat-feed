---
title: Prebid Server SSRF Vulnerability in Bidder Adapters
slug: 2026-07-prebid-server-ssrf
description: Prebid Server contains a Server-Side Request Forgery vulnerability (CVE-2026-54735) allowing unauthenticated attackers to force the server to perform arbitrary outbound HTTP requests.
date: "2026-07-29T16:01:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Prebid
products:
  - prebid-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw originates in certain bidder adapters that fail to perform adequate input validation on user-supplied parameters.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1212
    technique_name: Exploitation for Credential Access
    evidence: An attacker can exploit this to force the server to initiate requests to internal network resources, potentially leading to unauthorized data extraction.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4p3g-4hcj-wpvx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54735
---

Prebid Server is affected by a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-54735. The flaw originates in certain bidder adapters that fail to perform adequate input validation on user-supplied parameters before interpolating them into outbound request URLs. An attacker can supply malicious parameters in a bid request to force the Prebid Server instance to send HTTP requests to arbitrary destinations. This vulnerability enables attackers to perform reconnaissance on the internal network, interact with sensitive local endpoints, or exfiltrate metadata from the host environment. The vulnerability impacts Prebid Server versions prior to v4.4.0, as well as specific older release branches. Defenders should prioritize patching or disabling affected bidder adapters to mitigate unauthorized internal access.

## Impact

Successful exploitation allows an unauthenticated attacker to abuse the server as a proxy to reach internal resources that are otherwise inaccessible from the public internet. This can lead to the exposure of internal metadata services (e.g., cloud instance metadata), local administrative interfaces, or sensitive internal API endpoints. The severity is critical given the potential for unauthorized data extraction and lateral movement within the network hosting the Prebid Server instance.

## Recommendation

- Upgrade Prebid Server to version v4.4.0 or later to apply the necessary input validation logic.
- Disable any bidder adapters known to be susceptible to parameter injection if patching cannot be performed immediately.
- Implement egress filtering on the network hosting Prebid Server to restrict outbound connections to only verified and expected external bidder endpoints.
- Audit web server logs and proxy logs for anomalous HTTP requests originating from the Prebid Server application to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or local loopback addresses.
