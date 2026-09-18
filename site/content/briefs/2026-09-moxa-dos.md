---
title: Remote Denial of Service Vulnerability in Moxa TN-4500B Series
slug: 2026-09-moxa-dos
description: A critical out-of-bounds write vulnerability (CVE-2026-15579) in Moxa TN-4500B Series switches allows remote, unauthenticated attackers to cause a denial-of-service condition.
date: "2026-09-18T19:45:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:moxa:tn-4500b_series_firmware:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - industrial-control-systems
  - denial-of-service
  - network-device
vendors:
  - Moxa
products:
  - TN-4500B Series (< 2.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remote, unauthenticated attacker can exploit this vulnerability to trigger a denial-of-service (DoS) condition on the affected network device.
    confidence_band: high
cves:
  - id: CVE-2026-15579
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1205/
  - https://www.moxa.com/en/support/product-support/security-advisory/mpsa-252620-cve-2026-15579-out-of-bounds-write-vulnerability-in-ethernet-switch
  - https://www.cve.org/CVERecord?id=CVE-2026-15579
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware of all Moxa TN-4500B Series units to version 2.1 or later.
      owner: IT Operations
      addresses: CVE-2026-15579
      evidence: Moxa Security Advisory MPSA-252620
---

Moxa has released security advisory MPSA-252620 detailing an out-of-bounds write vulnerability, identified as CVE-2026-15579, affecting the TN-4500B Series of industrial Ethernet switches. The vulnerability exists due to improper handling of input within the device's management interface. A remote, unauthenticated attacker can exploit this flaw by sending specially crafted packets to the affected hardware. Successful exploitation results in an immediate denial-of-service (DoS) condition, rendering the network switch unavailable and potentially disrupting critical industrial communication flows. All versions of the TN-4500B series prior to version 2.1 are affected.

## Impact

The impact of this vulnerability is significant, as it permits the disruption of industrial network infrastructure from a remote, unauthenticated position. Organizations relying on the TN-4500B series for critical communications or SCADA operations face an increased risk of operational downtime and loss of visibility into the managed network segments if the device enters a crashed state.

## Recommendation

Prioritize the immediate patching of all vulnerable Moxa TN-4500B series switches.
* Upgrade all affected units to firmware version 2.1 or later as specified in Moxa Security Advisory MPSA-252620.
* Restrict network access to the switch management interfaces using firewalls or ACLs to prevent unauthenticated remote access to the vulnerable service until patching is complete.
