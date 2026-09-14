---
title: Remote Use-After-Free Vulnerability in Open5GS
slug: 2026-09-open5gs-uaf
description: A use-after-free vulnerability in the Open5GS AMF component allows remote attackers to trigger memory corruption via manipulated discovery options, potentially leading to service disruption or code execution.
date: "2026-09-14T11:33:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:open5gs:open5gs:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - open5gs
  - cve
vendors:
  - Open5GS
products:
  - Open5GS (<= 2.7.x)
cves:
  - id: CVE-2026-90707
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90707
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Upgrade Open5GS to a patched version incorporating commit ddd683a35f8aaac2b7b9884a24cd53bddfc65238
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-90707 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the Open5GS NNRF handler endpoint to known authorized network segments
      owner: Network Security
      addresses: CVE-2026-90707
      evidence: Network-based remote exploitation vulnerability
---

A critical use-after-free vulnerability, tracked as CVE-2026-90707, exists in Open5GS versions up to 2.7.x. The issue resides within the 'amf_nnrf_try_old_amf_discovery_fallback' function located in 'src/amf/nnrf-handler.c'. An attacker can remotely exploit this flaw by providing a crafted 'discovery_option' argument to the NNRF (Non-3GPP Interworking Function) handler. This manipulation causes the application to access memory after it has been freed, which may lead to application crashes or potentially arbitrary code execution in the context of the Open5GS service. Security teams should prioritize patching this component, as the Open5GS service acts as a core node in 5G network infrastructure.

## Impact

Successful exploitation of this vulnerability could result in a denial of service (DoS) through application process termination or, in more complex scenarios, arbitrary code execution on the underlying server. Because Open5GS is a critical component in 5G core networks, a service outage could disrupt network connectivity for connected users.

## Recommendation

- Upgrade all Open5GS installations to a version containing the fix identified by commit hash 'ddd683a35f8aaac2b7b9884a24cd53bddfc65238'.
- Monitor network traffic logs for anomalous NNRF API requests involving unexpected or overly long 'discovery_option' values that target the AMF component.
- Implement network segmentation to isolate the Open5GS AMF service from untrusted or external networks to limit the attack surface for remote exploitation.
