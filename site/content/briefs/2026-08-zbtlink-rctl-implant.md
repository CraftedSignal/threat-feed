---
title: ENDLESSDOORS Vulnerability Affecting Zbtlink Routers
slug: 2026-08-zbtlink-rctl-implant
description: Multiple Zbtlink router models are susceptible to the ENDLESSDOORS root implant, which leverages the rctl remote control tool for unauthorized access and persistent phone-home capabilities.
date: "2026-08-05T21:23:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - firmware-vulnerability
  - implant
  - router
  - network-security
  - informational
vendors:
  - Zbtlink
products:
  - CPE2801 Firmware
  - WE1026-5G-WD Firmware
  - WE1326 Firmware
  - WE2007 Firmware
  - WE2008-DSIM Firmware
  - WE2416 Firmware
  - WE3326 Firmware
  - WE5927 Firmware
  - WE5931 Firmware
  - WE5931AC Firmware
  - WE826-T3-DSIM Firmware
  - WG108 Firmware
  - WG1602 Firmware
  - WG1608-DSIM Firmware
  - WG209 Firmware
  - WG2105 Firmware
  - WG2107 Firmware
  - WG259 Firmware
  - WG3526 Firmware
  - ZBT-Z8102AX-2SIM Firmware
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The implant known as 'rctl' or 'kworker' provides root implant capabilities allowing for persistent remote control.
    confidence_band: high
references:
  - https://cyber.gc.ca/en/alerts-advisories/zbtlink-security-advisory-av26-779
  - https://www.vulncheck.com/advisories/zbt-endlessdoors
  - https://www.zbtlink.com/pages/zbt-router-firmware-download
---

Researchers have identified a significant security vulnerability in a wide range of Zbtlink wireless router firmware, collectively referred to as the ENDLESSDOORS threat. Attackers are exploiting this vulnerability to deploy a root-level implant, identified as 'rctl' or 'kworker'. The 'rctl' utility is a remote Linux control tool that provides attackers with persistent, unauthorized administrative access to the underlying operating system of the networking hardware. By establishing a phone-home communication mechanism, the implant enables remote command execution and exfiltration of sensitive network traffic. Given the wide array of affected firmware versions and models, this vulnerability represents a severe risk of long-term network compromise for organizations utilizing Zbtlink hardware. Defenders should review device configurations and monitor for unauthorized binary execution within the router's management interfaces or internal shell.

## Impact

Successful exploitation of the ENDLESSDOORS vulnerability allows for complete system compromise of the affected Zbtlink routers. This grants attackers the ability to intercept internal network traffic, manipulate DNS settings, gain persistent access to private segments of the network, and utilize the devices as part of a botnet. The wide scope of affected legacy and modern firmware versions impacts various small office and industrial networking deployments.

## Recommendation

- Identify all Zbtlink router models listed in this brief and isolate them from public-facing internet segments immediately.
- Audit all administrative logs on networking equipment for the execution of unexpected binaries, specifically processes labeled 'rctl' or 'kworker'.
- Verify firmware versions against the manufacturer's security download page and update to the latest provided images.
- Restrict administrative access to router interfaces to known, trusted internal management IP ranges.
- Implement outbound traffic filtering at the network perimeter to block unauthorized 'phone-home' or C2 traffic originating from infrastructure networking devices.
