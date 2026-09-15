---
title: Multiple Vulnerabilities in Siemens Reyrolle 7SR5 Firmware
slug: 2026-09-siemens-reyrolle-vulnerabilities
description: Siemens Reyrolle 7SR5 devices running firmware versions earlier than V2.70 are impacted by multiple vulnerabilities within the embedded Mongoose Web Server, potentially leading to denial of service, information disclosure, or authentication bypass.
date: "2026-09-15T16:31:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siemens:reyrolle_7sr5:*:*:*:*:*:*:*:*
tags:
  - ics
  - energy
  - firmware-vulnerability
vendors:
  - Siemens
products:
  - Reyrolle 7SR5 (< V2.70)
cves:
  - id: CVE-2026-62650
    cvss: 8.8
    epss: 0.00319
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-05
  - https://support.industry.siemens.com/cs/ww/en/view/109772413/
action_plan:
  priority: elevated
  owners:
    - IT/OT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all Siemens Reyrolle 7SR5 devices to firmware V2.70.
      owner: IT/OT Operations
      due: 72h
      evidence: Vendor recommendation for CVE mitigation.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to management ports of all Reyrolle 7SR5 devices.
      owner: Network Operations
      addresses: All CVEs listed in brief
      evidence: Reduction of attack surface for network-accessible vulnerabilities.
---

Siemens Reyrolle 7SR5 protection devices with firmware versions earlier than V2.70 contain multiple high-severity vulnerabilities derived from the integrated Cesanta Mongoose Web Server (v7.14). The identified security flaws include integer overflows, out-of-bounds pointer usage, improper neutralization of delimiters, and authentication bypass via predictable session identifiers. These issues affect critical energy infrastructure devices deployed globally.

An attacker with network access could exploit these vulnerabilities to cause service disruptions via segmentation faults, force memory disclosure, or bypass authentication mechanisms to gain unauthorized control over the device. Given the nature of these protection relays in energy sectors, successful exploitation could significantly impact operational availability and system integrity. Siemens has addressed these vulnerabilities in firmware version V2.70. Defenders are urged to prioritize patching to mitigate these risks.

The full list of associated vulnerabilities includes: CVE-2024-42384, CVE-2024-42385, CVE-2024-42386, CVE-2024-42391, CVE-2024-42392, CVE-2026-62645, CVE-2026-62646, CVE-2026-62647, CVE-2026-62648, CVE-2026-62649, CVE-2026-62650, CVE-2026-62652, CVE-2026-62653, and CVE-2026-62654.

## Impact

Successful exploitation of these vulnerabilities could result in the denial of service of protective relay functions, unauthorized access to device management interfaces via authentication bypass, and potential disclosure of sensitive system memory. These devices are critical components of global energy infrastructure; disruption could degrade grid reliability or interrupt industrial control processes.

## Recommendation

- Upgrade all Siemens Reyrolle 7SR5 devices to firmware version V2.70 or later immediately.
- Implement network segmentation to restrict access to the web management interfaces of industrial control devices to authorized management segments only.
- Monitor network traffic directed at Siemens Reyrolle device management interfaces for anomalous TLS packet structures or unusual HTTP request patterns associated with the web server.
