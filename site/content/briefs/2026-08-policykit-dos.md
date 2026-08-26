---
title: PolicyKit Local Denial of Service Vulnerability
slug: 2026-08-policykit-dos
description: A local, unprivileged attacker can exploit CVE-2024-41611 in PolicyKit to trigger a denial of service condition, potentially leading to system instability.
date: "2026-08-26T14:03:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:dlink:dir-860l_firmware:1.10b04:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - linux
vendors:
  - Polkit
products:
  - PolicyKit
cves:
  - id: CVE-2024-41611
    cvss: 9.8
    epss: 0.00776
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3021
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch PolicyKit to the latest version provided by distribution maintainers
      owner: IT Operations
      addresses: CVE-2024-41611
      evidence: Source advisory confirms CVE-2024-41611 vulnerability in PolicyKit
---

A vulnerability has been identified in PolicyKit, the component responsible for defining and handling authorization policies in Unix-like operating systems. An unprivileged local attacker can leverage this flaw to trigger a denial of service (DoS) state. By exploiting the underlying vulnerability, identified as CVE-2024-41611, an attacker can cause the PolicyKit service to become unresponsive or crash, which may impact system-wide authorization services. This vulnerability is significant because it allows a local user to disrupt core system operations that rely on PolicyKit for privileged access management. Defensive teams should prioritize patching or applying updates provided by their Linux distribution maintainers to address this instability.

## Impact

Successful exploitation results in a local denial of service. The impact includes the potential for system-wide service disruption, as many privileged operations rely on PolicyKit to validate user actions. This vulnerability affects systems where PolicyKit is active, primarily impacting Linux environments across all sectors.

## Recommendation

* Apply the security patches provided by your Linux distribution vendor to resolve CVE-2024-41611.
* Audit system logs for unexpected terminations or restarts of the `polkitd` process.
