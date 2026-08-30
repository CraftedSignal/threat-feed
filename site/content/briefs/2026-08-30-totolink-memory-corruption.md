---
title: Remote Memory Corruption in TOTOLINK A720R MAC Filtering
slug: 2026-08-30-totolink-memory-corruption
description: A remote memory corruption vulnerability in the TOTOLINK A720R router allows unauthenticated attackers to trigger a crash or potentially achieve code execution via the cstecgi.cgi script.
date: "2026-08-30T13:10:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:totolink:a720r:4.1.5cu.630_b20250509:*:*:*:*:*:*:*
vendors:
  - TOTOLINK
products:
  - A720R (4.1.5cu.630_B20250509)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82539
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82539
action_plan:
  priority: elevated
  owners:
    - Network Security
    - IT Operations
  immediate_actions:
    - action: Restrict management interface access to internal subnets.
      owner: Network Security
      due: 24h
      evidence: Publicly disclosed remote exploit potential.
  mitigation_plan:
    - priority: immediate
      action: Apply manufacturer firmware patch when available.
      owner: IT Operations
      addresses: CVE-2026-82539
      evidence: Vendor vulnerability advisory.
---

TOTOLINK A720R firmware version 4.1.5cu.630_B20250509 contains a critical memory corruption vulnerability identified as CVE-2026-82539. The flaw resides within the setMacFilterRules function of the cstecgi.cgi component, which handles MAC filtering configurations. An unauthenticated remote attacker can exploit this vulnerability by sending a maliciously crafted HTTP request containing an oversized or malformed 'desc' argument to the affected interface. This manipulation triggers a memory corruption condition, which may result in a device crash (Denial of Service) or potential arbitrary code execution. Given the public disclosure of exploit details, organizations utilizing these devices in internet-facing configurations are at significant risk of remote compromise.

## Impact

The vulnerability allows remote attackers to compromise the availability and integrity of TOTOLINK A720R network devices. Successful exploitation can lead to a complete denial of service for the network segment managed by the router or provide a foothold for further unauthorized access into the internal network environment.

## Recommendation

1. Restrict administrative access to the router's web interface to trusted management subnets only.
2. Monitor incoming HTTP traffic directed at the cstecgi.cgi endpoint for anomalous request patterns or excessively long arguments in the 'desc' parameter.
3. Consult the vendor for firmware update availability and apply patches immediately once released.
4. Implement network-level egress filtering to prevent exploited devices from reaching external command and control infrastructure.
