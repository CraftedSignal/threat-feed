---
title: Denial-of-Service Vulnerability in Hirschmann HiOS Switch Platform
slug: 2026-09-hirschmann-dos
description: Hirschmann HiOS Switch Platform devices are susceptible to a remote unauthenticated denial-of-service vulnerability due to improper input validation in the integrated web server.
date: "2026-09-15T15:41:03Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:hirschmann:hios_switch_platform:*:*:*:*:*:*:*:*
vendors:
  - Hirschmann
products:
  - HiOS Switch Platform (< 07.1.12, 08.7.10, 09.0.13, 09.3.03, 10.3.08, 10.5.00)
cves:
  - id: CVE-2026-89025
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89025
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade HiOS firmware to version 07.1.12, 08.7.10, 09.0.13, 09.3.03, 10.3.08, or 10.5.00
      owner: Network Security
      addresses: CVE-2026-89025
      evidence: The source documentation identifies these versions as addressing the vulnerability.
---

Hirschmann HiOS Switch Platform devices contain a denial-of-service vulnerability in their integrated web server. The flaw arises from missing validation of HTTP(S) content processed by the device. A remote, unauthenticated attacker can exploit this by sending a specially crafted HTTP(S) request to a specific endpoint, which triggers an unintended reboot of the switch. This results in a temporary denial-of-service condition for the device and any traffic passing through it. The vulnerability is tracked as CVE-2026-89025. Hirschmann has released security updates to address this issue, and administrators are advised to verify firmware versions against the patched releases.

## Impact

Successful exploitation results in an immediate and temporary denial-of-service of Hirschmann network switches, which can disrupt critical infrastructure communication. Affected sectors include industrial control systems and enterprise network environments where HiOS-based switches are deployed to manage traffic. Impact is limited to device availability due to forced reboots.

## Recommendation

- Upgrade affected Hirschmann HiOS firmware to the patched versions: 07.1.12, 08.7.10, 09.0.13, 09.3.03, 10.3.08, or 10.5.00.
- Restrict access to the management web interface of network switches to trusted management subnets or via out-of-band management networks to minimize the attack surface for CVE-2026-89025.
