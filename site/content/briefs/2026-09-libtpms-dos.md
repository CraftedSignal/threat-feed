---
title: Denial of Service Vulnerability in libtpms
slug: 2026-09-libtpms-dos
description: A vulnerability in libtpms (CVE-2024-0230) allows an attacker on an adjacent network to trigger a denial of service condition, potentially leading to service instability.
date: "2026-09-08T19:34:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ibm:libtpms:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:magic_keyboard_firmware:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - virtualization
vendors:
  - IBM
products:
  - libtpms
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker from an adjacent network can exploit a vulnerability in libtpms to perform a denial of service attack.
    confidence_band: high
cves:
  - id: CVE-2024-0230
    cvss: 2.4
    epss: 0.01223
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3216
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Patch libtpms to the version provided by the vendor or distribution package maintainer
      owner: IT Operations
      addresses: CVE-2024-0230
      evidence: Source advisory states the library contains a DoS vulnerability.
---

A vulnerability has been identified in libtpms, a library providing software emulation of a Trusted Platform Module (TPM). The flaw, tracked as CVE-2024-0230, allows an unauthenticated attacker located on an adjacent network to cause a denial of service (DoS) condition. This vulnerability is triggered by improper processing of specific requests sent to the library, which can lead to system instability or service disruption for applications relying on libtpms for TPM functionality. Because the attack requires access to an adjacent network, the impact is primarily relevant to hypervisors, virtualization hosts, or container environments utilizing emulated TPMs where network segmentation might be bypassed or misconfigured. Organizations using virtualization stacks that incorporate libtpms should prioritize evaluating their exposure and applying updates provided by their distribution or vendor.

## Impact

The vulnerability impacts the availability of systems and services that depend on libtpms. A successful exploit results in a denial of service, forcing a restart or crash of the affected TPM-reliant component. This is particularly concerning for cloud infrastructure providers or high-density virtualization environments where a single host service failure could disrupt multiple hosted workloads.

## Recommendation

- Monitor virtualization host logs for unexpected service restarts of TPM-related processes.
- Apply the latest security updates for libtpms provided by your Linux distribution maintainer to address CVE-2024-0230.
- Review network segmentation policies to ensure that management interfaces or virtualization backends are not exposed to untrusted adjacent network segments.
