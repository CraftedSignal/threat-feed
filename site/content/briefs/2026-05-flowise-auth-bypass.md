---
title: Flowise < 3.0.5 Missing Authentication Vulnerability Exploitable
slug: 2026-05-flowise-auth-bypass
description: A missing authentication vulnerability in Flowise versions prior to 3.0.5 allows attackers to perform critical functions without authentication, and a working exploit is publicly available on Exploit-DB.
date: "2026-05-13T13:03:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - flowise
  - authentication bypass
  - web application
  - exploit-db
products:
  - Flowise (< 3.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.exploit-db.com/exploits/52557
rules:
  - title: Detect Flowise Missing Authentication Exploit Attempt
    description: Detects attempts to exploit the Flowise missing authentication vulnerability based on suspicious URI patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Flowise Critical Function Access Without Authentication
    description: Detects access to critical Flowise functions without prior authentication, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability exists in Flowise, an open-source visual flow builder for AI automation, affecting versions prior to 3.0.5. This vulnerability, classified as a Missing Authentication for Critical Function, allows unauthenticated attackers to perform sensitive actions within the application. A public exploit (EDB-52557) demonstrating this vulnerability has been published on Exploit-DB, significantly increasing the risk to unpatched Flowise instances. The absence of authentication checks on critical functions could lead to unauthorized access, data manipulation, and complete compromise of the Flowise application and potentially the underlying system.

## Attack Chain

1.  Attacker identifies a vulnerable Flowise instance running a version prior to 3.0.5.
2.  Attacker sends a crafted HTTP request to a critical function endpoint lacking authentication, as detailed in the Exploit-DB entry.
3.  The vulnerable Flowise instance processes the request without verifying user identity.
4.  Attacker leverages the missing authentication to bypass access controls.
5.  Attacker executes privileged functions, potentially including reading/writing data.
6.  Attacker modifies or deletes existing Flowise workflows.
7.  Attacker injects malicious code into existing workflows.
8.  The attacker achieves complete control over the Flowise instance, potentially leading to further lateral movement or data exfiltration.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform critical functions within Flowise. This can lead to unauthorized data access, modification, or deletion of sensitive workflows. An attacker could potentially inject malicious code into existing flows, leading to supply chain attacks or further compromise of connected systems. The availability of a public exploit makes exploitation easier, increasing the likelihood of attacks against vulnerable Flowise instances.

## Recommendation

*   Upgrade Flowise to version 3.0.5 or later to patch the missing authentication vulnerability.
*   Deploy the Sigma rules below to your SIEM to detect exploitation attempts against Flowise.
*   Monitor web server logs for suspicious requests to Flowise endpoints, especially those targeting critical functions.
*   Implement strong network segmentation and access controls to limit the impact of a potential compromise.
