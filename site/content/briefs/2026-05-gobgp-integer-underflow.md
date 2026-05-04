---
title: osrg GoBGP Integer Underflow Vulnerability
slug: 2026-05-gobgp-integer-underflow
description: osrg GoBGP up to version 4.3.0 is vulnerable to an integer underflow in the parseRibEntry function, potentially allowing a remote attacker to cause a denial of service or other unspecified impacts; version 4.4.0 addresses this issue.
date: "2026-05-04T07:16:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - vulnerability
  - integer underflow
  - bgp
vendors:
  - osrg
products:
  - GoBGP (<= 4.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7736
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7736
  - https://github.com/osrg/gobgp/
  - https://github.com/osrg/gobgp/commit/76d911046344a3923cbe573364197aa081944592
  - https://github.com/osrg/gobgp/releases/tag/v4.4.0
  - https://vuldb.com/submit/807604
  - https://vuldb.com/vuln/360911
  - https://vuldb.com/vuln/360911/cti
rules:
  - title: Detect Potentially Malicious MRT Messages to GoBGP
    description: Detects network connections to the BGP port (179) that might carry malicious MRT messages targeting GoBGP instances.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595
    data_sources:
      - network_connection
      - linux
  - title: Detect GoBGP Process Crash
    description: Detects when GoBGP process crashes indicating a possible vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in osrg GoBGP, specifically in versions up to 4.3.0. The flaw is located within the `parseRibEntry` function of the `pkg/packet/mrt/mrt.go` file. This integer underflow vulnerability, identified as CVE-2026-7736, can be triggered remotely by an attacker who sends malicious or unexpected data to the affected function. Successful exploitation could lead to a denial-of-service condition or other unspecified consequences. Users are advised to upgrade to version 4.4.0, which contains the patch identified as 76d911046344a3923cbe573364197aa081944592, to mitigate the risk. The vulnerability poses a risk to network infrastructure relying on the BGP protocol, potentially impacting routing stability and availability.

## Attack Chain

1. An attacker identifies a vulnerable GoBGP instance running a version prior to 4.4.0.
2. The attacker crafts a malicious MRT (Multi-Threaded Routing Toolkit) message.
3. The attacker sends the crafted MRT message to the vulnerable GoBGP instance. This is typically done over a TCP connection to the BGP port (179).
4. The `parseRibEntry` function processes the malicious MRT message.
5. Due to the integer underflow vulnerability, the `parseRibEntry` function calculates an incorrect value.
6. This incorrect value leads to unexpected behavior such as a crash or resource exhaustion.
7. The GoBGP process becomes unstable or terminates.
8. This disrupts BGP routing, potentially leading to a denial-of-service condition for network services that rely on BGP.

## Impact

Successful exploitation of this vulnerability could allow a remote attacker to disrupt BGP routing, leading to a denial-of-service condition. The precise impact will depend on the specific network configuration and the role of the affected GoBGP instance. Systems relying on the BGP protocol for routing information could experience connectivity issues or routing instability. While the number of affected deployments is unknown, any organization utilizing GoBGP in their network infrastructure is potentially at risk.

## Recommendation

*   Upgrade to GoBGP version 4.4.0 or later to remediate the integer underflow vulnerability described in CVE-2026-7736.
*   Monitor network traffic for unexpected MRT messages being sent to GoBGP instances using the Sigma rule provided below.
*   Review and harden BGP configurations to limit exposure and potential attack surface.
