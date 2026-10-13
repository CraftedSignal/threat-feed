---
title: Remote Stack-Based Buffer Overflow in TRENDnet TEW-432BRP
slug: 2026-10-trendnet-tew-432brp-overflow
description: The TRENDnet TEW-432BRP router (version 3.10B20) is susceptible to remote code execution via a stack-based buffer overflow in the /goform/formTcpipSetup function.
date: "2026-10-13T12:35:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:trendnet:tew-432brp:3.10b20:*:*:*:*:*:*:*
vendors:
  - TRENDnet
products:
  - TEW-432BRP (3.10B20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Performing a manipulation of the argument Name results in stack-based buffer overflow. It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-109157
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109157
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Decommission all TRENDnet TEW-432BRP hardware
      owner: IT Operations
      due: 72h
      evidence: Product is EOL since 2011 and no patches are available
  mitigation_plan:
    - priority: immediate
      action: Isolate device from the internet and internal networks via VLAN
      owner: IT Operations
      addresses: CVE-2026-109157
      evidence: Remote code execution risk on internet-facing device
---

The TRENDnet TEW-432BRP router (version 3.10B20) contains a critical stack-based buffer overflow vulnerability identified as CVE-2026-109157. The vulnerability exists within the 'formTcpipSetup' function, which fails to properly validate the 'Name' argument when processing requests sent to the '/goform/formTcpipSetup' endpoint. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted HTTP request to the device, potentially leading to remote code execution. Public exploit code for this vulnerability is available, increasing the risk of exploitation. TRENDnet has confirmed that this device reached end-of-life (EOL) in 2011 and will not receive official security patches, leaving deployed units permanently vulnerable.

## Impact

Successful exploitation allows for unauthenticated remote code execution on the target router. This provides attackers with full control over the network gateway, enabling traffic interception, man-in-the-middle attacks, and internal network reconnaissance. Given the EOL status, there is no path to remediation, and organizations must isolate or replace affected hardware to mitigate the risk of compromise.

## Recommendation

Prioritize the decommissioning and replacement of all identified TRENDnet TEW-432BRP routers as no patches exist for this device. Implement network segmentation to isolate legacy networking hardware from production environments. Utilize network-based intrusion detection systems to monitor for anomalous HTTP requests targeting the '/goform/formTcpipSetup' URI.
