---
title: Use-After-Free Vulnerability in cJSON cJSONUtils_MergePatch
slug: 2026-09-cjson-use-after-free
description: A publicly exploitable use-after-free vulnerability in the cJSONUtils_MergePatch function of the DaveGamble cJSON library allows for potential remote code execution or application crashes.
date: "2026-09-10T03:03:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:davegamble:cjson:*:*:*:*:*:*:*:*
vendors:
  - DaveGamble
products:
  - cJSON (<= 1.7.19)
cves:
  - id: CVE-2026-87933
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87933
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory software utilizing DaveGamble cJSON library
      owner: Security Architecture
      due: 48h
      evidence: Source confirms vulnerability in DaveGamble cJSON up to 1.7.19
  mitigation_plan:
    - priority: immediate
      action: Monitor repository for patched cJSON version and upgrade all affected instances
      owner: IT Operations
      addresses: CVE-2026-87933
      evidence: Source notes that a pull request to fix the issue awaits acceptance
---

A use-after-free vulnerability (CVE-2026-87933) has been identified in the DaveGamble cJSON library, specifically within the cJSONUtils_MergePatch function in the file cJSON_Utils.c. The vulnerability affects all versions of the library up to and including 1.7.19. The flaw occurs due to improper memory management during the JSON merge patch operation, which can be triggered remotely. Given that a proof-of-concept exploit has been made public, there is a risk of exploitation by unauthenticated remote attackers. The vulnerability allows for arbitrary code execution or service disruption through memory corruption. At the time of this brief, an official patch for this issue is pending acceptance via a pull request. Defenders should audit applications utilizing cJSON 1.7.19 or earlier and prepare to upgrade once a stable fix is merged and released.

## Impact

The impact of this vulnerability is significant, as cJSON is a widely used C library for JSON parsing. Successful exploitation can lead to unauthorized code execution, arbitrary memory access, or denial of service by crashing the application. Applications that accept and process external, untrusted JSON data via the vulnerable cJSONUtils_MergePatch function are at the highest risk.

## Recommendation

Prioritize the identification of applications within the environment that statically or dynamically link against the DaveGamble cJSON library version 1.7.19 or earlier.

Monitor vendor repositories for the final merge and release of the fix for CVE-2026-87933. Once the patch is available, schedule an immediate update for all affected software. Given the availability of public exploits, prioritize internal applications that process user-supplied JSON input from the public internet.
