---
title: Anviz CX2 Lite and CX7 Unauthenticated Debug Setting Modification
slug: 2026-04-anviz-auth-bypass
description: Anviz CX2 Lite and CX7 devices are vulnerable to unauthenticated POST requests that allow modification of debug settings such as enabling SSH, leading to unauthorized state changes and potential compromise.
date: "2026-04-17T20:16:36Z"
type: advisory
types:
  - advisory
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

CVE-2026-40461 describes a vulnerability affecting Anviz CX2 Lite and CX7 devices. The vulnerability allows unauthenticated attackers to send POST requests that modify debug settings on the devices. A successful exploit can enable features like SSH, which are normally restricted. This unauthorized configuration change could be leveraged to gain unauthorized access to the device and potentially the network it is connected to, allowing for further malicious activity. The vulnerability was disclosed in April 2026 and poses a significant risk to organizations using the affected Anviz devices for access control.

## Attack Chain

1. The attacker identifies an Anviz CX2 Lite or CX7 device on the network.
2. The attacker sends an unauthenticated POST request to the device's web interface.
3. The POST request targets a specific endpoint responsible for modifying debug settings.
4. The request includes parameters that enable debug features, such as SSH.
5. The device improperly processes the request without requiring authentication, modifying the debug settings accordingly.
6. The attacker uses the newly enabled SSH service to gain shell access to the device.
7. The attacker leverages the gained access to escalate privileges, move laterally within the network, or exfiltrate sensitive information.

## Impact

Successful exploitation of CVE-2026-40461 allows an attacker to modify device settings, potentially enabling unauthorized access and control over Anviz CX2 Lite and CX7 devices. This can lead to a compromise of the physical security system and potentially the entire network. The impact includes unauthorized entry, data breaches, and disruption of operations. The number of affected devices and organizations is currently unknown.

## Recommendation

*   Monitor network traffic for POST requests targeting Anviz CX2 Lite and CX7 devices attempting to modify debug settings. Deploy the Sigma rule `Detect Anviz Debug Setting Modification` to identify such activity.
*   Implement network segmentation to isolate Anviz devices from critical network resources to limit the impact of a potential compromise.
*   Consult the vendor's website (https://www.anviz.com/contact-us.html) and CISA advisory (https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03) for any available patches or mitigations.
