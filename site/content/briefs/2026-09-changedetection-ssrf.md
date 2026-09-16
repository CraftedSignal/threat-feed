---
title: SSRF Vulnerability in changedetection.io
slug: 2026-09-changedetection-ssrf
description: changedetection.io versions 0.60.6 and earlier contain a Server-Side Request Forgery (SSRF) vulnerability allowing unauthenticated attackers to access internal network resources.
date: "2026-09-16T21:58:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:changedetection_io:changedetection_io:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
vendors:
  - changedetection.io
products:
  - changedetection.io (<= 0.60.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The application fails to validate the Goto URL action within browser steps, allowing unauthenticated attackers to supply arbitrary internal URLs via the optional_value parameter.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Attackers can supply arbitrary internal URLs in the optional_value parameter to retrieve responses from restricted network locations.
    confidence_band: high
cves:
  - id: CVE-2026-92815
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92815
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade changedetection.io to version > 0.60.6
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92815 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict changedetection.io network access to internal subnets via firewall or network policy
      owner: IT Operations
      addresses: CVE-2026-92815
      evidence: Mitigates SSRF network probing capability
---

changedetection.io versions up to and including 0.60.6 are susceptible to a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-92815. The flaw resides in the handling of the 'Goto URL' action within browser steps. By manipulating the 'optional_value' parameter, an unauthenticated attacker can force the application to make HTTP requests to arbitrary internal IP addresses or services that are otherwise unreachable from the public internet. This allows for the discovery of internal infrastructure, unauthorized access to internal web services, and potential data exfiltration of internal-only content. Defenders should identify instances of changedetection.io and restrict the service's ability to initiate connections to sensitive internal networks.

## Impact

Successful exploitation of this vulnerability allows unauthenticated actors to bypass network perimeter controls to probe internal resources. This can lead to the exposure of sensitive internal service configurations, metadata, or data contained within an organization's private network segment that the changedetection.io instance has network visibility into.

## Recommendation

Prioritize patching all affected changedetection.io instances to a version later than 0.60.6. Implement network-level egress filtering to restrict the changedetection.io service container or host from reaching private IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and sensitive management interfaces.
