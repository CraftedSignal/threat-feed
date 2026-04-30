---
title: EVerest EV Charging Stack Data Race Vulnerability (CVE-2026-26074)
slug: 2026-03-everest-data-race
description: EVerest versions prior to 2026.02.0 exhibit a data race vulnerability (CVE-2026-26074) where concurrent network requests and physical events can corrupt the event queue, leading to potential denial of service or other undefined behavior.
date: "2026-03-26T17:16:33Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-26074
  - data-race
  - ev-charging
  - everest
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26074
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-p3hg-vqgv-h524
rules:
  - title: Detect EVerest CSMS GetLog/UpdateFirmware Request
    description: Detects network connections indicative of a CSMS GetLog or UpdateFirmware request to an EVerest charging station, which may precede a CVE-2026-26074 exploitation attempt when combined with a physical EVSE fault.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - linux
  - title: EVerest Crash due to Event Queue Corruption
    description: Detects a crash or error message in EVerest logs that indicates corruption of the event queue, potentially triggered by CVE-2026-26074.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - webserver
      - linux
rules_count: 2
---

EVerest, an EV charging software stack, is susceptible to a data race vulnerability identified as CVE-2026-26074. This flaw affects versions prior to 2026.02.0. The vulnerability arises from concurrent access to the `event_queue`, specifically a `std::map<std::queue>`, when a CSMS (Charging Station Management System) GetLog or UpdateFirmware request (originating from the network) coincides with an EVSE (Electric Vehicle Supply Equipment) fault event (a physical occurrence). This combination of…
