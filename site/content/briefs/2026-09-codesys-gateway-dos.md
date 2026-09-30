---
title: Denial-of-Service Vulnerability in CODESYS Gateway Client
slug: 2026-09-codesys-gateway-dos
description: An unauthenticated remote attacker can cause a denial-of-service in the CODESYS Gateway Client by providing a malicious gateway response that forces excessive memory allocation.
date: "2026-09-30T14:35:11Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:codesys:gateway_client:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
vendors:
  - CODESYS
products:
  - Gateway Client
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker controlling a malicious gateway can exploit this behavior to trigger excessive memory consumption, resulting in a denial-of-service condition.
    confidence_band: high
cves:
  - id: CVE-2026-76992
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76992
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate untrusted gateway endpoints communicating with the internal CODESYS Gateway Client
      owner: Security Operations
      addresses: CVE-2026-76992
      evidence: NVD vulnerability disclosure
---

The CODESYS Gateway Client is susceptible to a denial-of-service vulnerability (CVE-2026-76992) caused by improper input validation. The application allocates memory based on a size field provided within a gateway response without verifying if that size exceeds reasonable or safe limits. An unauthenticated, remote attacker who controls a malicious or compromised gateway server can send a crafted response with an abnormally large size value. When the Gateway Client attempts to process this response, it performs an oversized memory allocation, leading to exhaustion of system resources and a total loss of availability for the service. This vulnerability highlights the importance of enforcing strict validation on all data structures received from untrusted or external network infrastructure components.

## Impact

Successful exploitation leads to a denial-of-service condition, rendering the CODESYS Gateway Client unresponsive. This impact is critical for environments relying on CODESYS for industrial automation and process control, as the loss of gateway availability disrupts communication between the engineering environment and field devices. 

## Recommendation

Prioritized actions for security operations and IT teams:

- Audit network egress and ingress traffic to identify unauthorized or rogue CODESYS gateway servers communicating with the local Gateway Client.
- Implement network segmentation to ensure that the Gateway Client only communicates with verified and trusted gateway endpoints.
- Apply patches for CVE-2026-76992 as soon as they are made available by the vendor to remediate the unsafe memory allocation logic.
- Monitor system logs for unexpected application crashes or resource exhaustion events involving the CODESYS Gateway Client process.
