---
title: Multiple Denial of Service Vulnerabilities in Dell Intel NPU Driver
slug: 2026-09-dell-npu-dos
description: Multiple vulnerabilities in the Dell Intel NPU driver allow a local attacker to cause a denial of service condition through insufficient input validation.
date: "2026-09-10T12:53:29Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - hardware-driver
vendors:
  - Dell
products:
  - Intel NPU Driver
affected_os:
  - Windows
cves:
  - id: CVE-2024-38600
    cvss: 5.5
    epss: 0.00194
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3288
  - https://nvd.nist.gov/vuln/detail/CVE-2024-38600
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected Dell systems with the latest Intel NPU driver update
      owner: IT Operations
      due: 7d
      evidence: Vulnerability reported by BSI/CERT-Bund requiring vendor driver update
  mitigation_plan:
    - priority: short_term
      action: Identify systems with outdated Intel NPU driver versions using asset inventory tools
      owner: IT Operations
      addresses: CVE-2024-38600
      evidence: General patch management best practice for local DoS vulnerability
---

Multiple vulnerabilities have been identified in the Intel NPU driver for Dell computer systems. These flaws, which include CVE-2024-38600, stem from insufficient input validation within the driver component. A local attacker with low-privilege access to an affected machine can exploit these vulnerabilities to trigger a system crash, resulting in a denial of service (DoS) state. Because the issue resides in the kernel-mode driver, successful exploitation results in the destabilization of the NPU service, potentially requiring a system reboot to restore functionality. Defender teams should prioritize the application of vendor-supplied driver updates to mitigate the risk of local instability and service disruption.

## Impact

Successful exploitation of these vulnerabilities leads to a denial of service state, where the NPU driver fails or causes the host system to become unresponsive. This impacts users running Dell hardware equipped with Intel NPU capabilities. While the exploitation requires local access, it poses a risk to system availability in shared environments or on machines where non-administrator users have successfully compromised a local account.

## Recommendation

Prioritize the deployment of updated Dell Intel NPU driver software. Use your enterprise endpoint management solution to identify devices running vulnerable driver versions and distribute the patch provided by Dell.
