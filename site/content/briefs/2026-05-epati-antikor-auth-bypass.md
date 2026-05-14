---
title: ePati Antikor NGFW 2.0.1301 Authentication Bypass Vulnerability
slug: 2026-05-epati-antikor-auth-bypass
description: A public exploit has been published for ePati Antikor NGFW 2.0.1301, exploiting an authentication bypass vulnerability, increasing the risk to unpatched systems.
date: "2026-05-14T13:03:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication bypass
  - webapps
vendors:
  - ePati
products:
  - Antikor NGFW 2.0.1301
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.exploit-db.com/exploits/52562
rules:
  - title: Detect ePati Antikor NGFW Authentication Bypass Attempt
    description: Detects attempts to exploit the ePati Antikor NGFW authentication bypass vulnerability by monitoring for suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A public webapps exploit has been published on Exploit-DB for ePati Antikor NGFW 2.0.1301, demonstrating an authentication bypass vulnerability (EDB-52562). The availability of a working exploit significantly elevates the risk for unpatched systems, as attackers can potentially gain unauthorized access to the NGFW's administrative interface and sensitive data. This exploit allows attackers to bypass authentication mechanisms, potentially leading to complete compromise of the affected system. Defenders need to prioritize patching or implementing mitigations to prevent potential exploitation.

## Attack Chain

1. Attacker identifies a vulnerable ePati Antikor NGFW 2.0.1301 instance exposed to the network.
2. Attacker crafts a malicious HTTP request leveraging the authentication bypass vulnerability.
3. The crafted request is sent to the target NGFW instance.
4. The NGFW fails to properly validate the attacker's identity due to the authentication bypass.
5. The attacker gains unauthorized access to the administrative interface.
6. The attacker modifies firewall rules to allow malicious traffic.
7. The attacker gains access to sensitive network data and configurations.
8. The attacker may install backdoors or further compromise internal systems.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authentication and gain unauthorized access to the ePati Antikor NGFW 2.0.1301. This can lead to complete compromise of the firewall, allowing attackers to modify firewall rules, gain access to sensitive network data, and potentially pivot to internal systems. The impact includes data breaches, network disruptions, and further compromise of the internal network.

## Recommendation

- Deploy the Sigma rule provided in this brief to your SIEM to detect exploitation attempts against ePati Antikor NGFW (rule: "Detect ePati Antikor NGFW Authentication Bypass Attempt").
- Analyze web server logs for suspicious requests targeting the ePati Antikor NGFW administrative interface to identify potential exploitation attempts.
- Upgrade ePati Antikor NGFW to a patched version that addresses the authentication bypass vulnerability.
