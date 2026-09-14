---
title: Integer Overflow Vulnerability in Gravity JSON Parser
slug: 2026-09-gravity-integer-overflow
description: An integer overflow vulnerability (CVE-2026-90715) in the Gravity library's udp json-parser allows remote attackers to trigger application crashes or potential arbitrary code execution.
date: "2026-09-14T13:33:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:marcobambini:gravity:*:*:*:*:*:*:*:*
vendors:
  - marcobambini
products:
  - Gravity (<= 0.9.7)
cves:
  - id: CVE-2026-90715
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90715
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Gravity library to version 0.9.8
      owner: IT Operations
      due: 48h
      evidence: Upgrading to version 0.9.8 mitigates this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch Gravity library to 0.9.8
      owner: IT Operations
      addresses: CVE-2026-90715
      evidence: Upgrading to version 0.9.8 mitigates this issue.
---

A security vulnerability has been identified in the Gravity library, specifically within the udp json-parser component located in src/utils/gravity_json.c. The flaw, tracked as CVE-2026-90715, affects all versions up to and including 0.9.7. The vulnerability stems from an integer overflow condition that can be triggered remotely. If successfully exploited, the vulnerability may allow an attacker to crash the host application or potentially achieve arbitrary code execution, depending on the memory layout of the surrounding process. Public disclosure of exploitation vectors has been observed, making immediate remediation necessary for systems utilizing the Gravity library for JSON processing.

## Impact

The vulnerability affects applications relying on the Gravity library for processing JSON data over UDP. Successful exploitation can result in a denial of service (application crash) or potential compromise of the host system. Given the remote accessibility of the attack vector, organizations running software that integrates Gravity version 0.9.7 or earlier are at risk of remote exploitation.

## Recommendation

- Upgrade the Gravity library to version 0.9.8 or later immediately to incorporate the patch (commit 9b337c3eae5833c3956bed1fc01c21c14fd443f2).
- Review internal applications for dependencies on the marcobambini Gravity library and prioritize patching for any internet-facing services or services that process untrusted network input.
