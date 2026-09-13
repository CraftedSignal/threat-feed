---
title: Authentication Bypass in WARP-Clash-API via SECRET_KEY Manipulation
slug: 2026-09-warp-clash-api-auth-bypass
description: A publicly disclosed vulnerability in the WARP-Clash-API authorized function allows remote unauthenticated access by manipulating the SECRET_KEY argument.
date: "2026-09-13T11:25:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vvbbnn00:warp_clash_api:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-security
  - unmaintained-software
vendors:
  - vvbbnn00
products:
  - WARP-Clash-API (<= c7bf2360073959861219b422e51ae86411051b46)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90504
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90504
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and decommission all deployments of WARP-Clash-API
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-90504 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Isolate affected instances via network firewall rules
      owner: SOC
      addresses: CVE-2026-90504
      evidence: Unmaintained product with no available patch
---

CVE-2026-90504 is a high-severity authentication bypass vulnerability affecting the vvbbnn00 WARP-Clash-API, specifically within the 'authorized' function. The vulnerability stems from improper handling of the SECRET_KEY argument, which allows a remote, unauthenticated attacker to bypass security controls. The issue exists in all versions up to commit hash c7bf2360073959861219b422e51ae86411051b46. Because the software is no longer maintained and the vendor did not respond to disclosure, no official security patch is available. Defenders should prioritize identifying and decommissioning instances of this software, as exploitation is publicly documented and does not require complex prerequisites.

## Impact

The vulnerability results in a complete failure of authentication for the affected API. An attacker successfully exploiting this flaw can gain unauthorized access to the application, potentially leading to unauthorized data access, system manipulation, or further exploitation of underlying infrastructure depending on the API's permissions. Given the product's unmaintained status, affected systems remain permanently exposed to this risk.

## Recommendation

- Perform a network discovery scan to identify any instances of WARP-Clash-API running in the environment.
- Decommission or isolate all identified instances of this software immediately, as no patch exists to mitigate the vulnerability.
- Implement strict network-level access controls to restrict access to the API endpoints to authorized management IP addresses only, pending full removal.
