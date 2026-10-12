---
title: Authorization Bypass in Zoraxy via Path Exception Matcher
slug: 2026-10-zoraxy-auth-bypass
description: Zoraxy versions up to 3.3.4 are vulnerable to a remote authorization bypass in the Path Exception Matcher component that allows attackers to manipulate PathPrefix arguments.
date: "2026-10-12T18:32:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tobychui:zoraxy:*:*:*:*:*:*:*:*
vendors:
  - tobychui
products:
  - Zoraxy (<= 3.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-108899
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108899
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Zoraxy to 3.3.5-rc1
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 3.3.5-rc1 will fix this issue.
  mitigation_plan:
    - priority: immediate
      action: Apply patch 37cd0f27b17cd15cfa4af409bfec943146f5fdfe
      owner: IT Operations
      addresses: CVE-2026-108899
      evidence: 'Patch name: 37cd0f27b17cd15cfa4af409bfec943146f5fdfe.'
---

Zoraxy versions up to 3.3.4 contain a critical vulnerability in the `handleBasicAuth` function within `mod/dynamicproxy/authProviders.go`. The issue stems from the Path Exception Matcher component failing to properly validate the `PathPrefix` argument during authorization checks. By manipulating this argument, a remote, unauthenticated attacker can bypass existing authentication controls. The flaw is documented as CVE-2026-108899 and is reported to have public exploit code available, increasing the risk of exploitation by threat actors. Organizations utilizing Zoraxy as a reverse proxy or dynamic routing solution should prioritize patching, as successful exploitation results in unauthorized access to internal resources protected by the proxy.

## Impact

The vulnerability allows unauthorized access to backend services that rely on Zoraxy for Basic Authentication enforcement. This bypass can lead to the exposure of sensitive internal data, unauthorized administrative access, or facilitate further exploitation of protected backend applications. Given the nature of Zoraxy as a proxy, this flaw affects any network sector or infrastructure segment where the proxy is deployed as a gatekeeper.

## Recommendation

* Immediately upgrade all instances of Zoraxy to version 3.3.5-rc1 or newer to remediate the vulnerability associated with CVE-2026-108899.
* If an immediate upgrade is not feasible, apply the source code patch provided in commit 37cd0f27b17cd15cfa4af409bfec943146f5fdfe.
* Review logs for unusual requests to endpoints typically protected by Basic Auth that deviate from standard organizational traffic patterns, specifically looking for anomalous `PathPrefix` parameters.
