---
title: Anviz CX2 Lite and CX7 Unauthenticated Debug Setting Modification
slug: 2026-04-anviz-auth-bypass
description: Anviz CX2 Lite and CX7 devices are vulnerable to unauthenticated POST requests that allow modification of debug settings such as enabling SSH, leading to unauthorized state changes and potential compromise.
date: "2026-04-17T20:16:36Z"
severities:
  - high
tags:
  - cve-2026-40461
  - authentication-bypass
  - iot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40461
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40461
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
rules:
  - title: Detect Anviz Debug Setting Modification
    description: Detects POST requests to Anviz devices that attempt to modify debug settings by looking for specific URIs and parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Anviz Device User Agent
    description: Detects network connections using the Anviz device's default user agent.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-40461 describes a vulnerability affecting Anviz CX2 Lite and CX7 devices. The vulnerability allows unauthenticated attackers to send POST requests that modify debug settings on the devices. A successful exploit can enable features like SSH, which are normally restricted. This unauthorized configuration change could be leveraged to gain unauthorized access to the device and potentially the network it is connected to, allowing for further malicious activity. The vulnerability was…
