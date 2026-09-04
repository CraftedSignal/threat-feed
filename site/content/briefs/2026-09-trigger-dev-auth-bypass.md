---
title: Authorization Bypass in Trigger.dev Run Replay Operation
slug: 2026-09-trigger-dev-auth-bypass
description: Trigger.dev versions prior to 4.5.2 contain an improper authorization vulnerability that allows authenticated attackers to inject task runs into arbitrary environments.
date: "2026-09-04T17:26:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:trigger:trigger.dev:*:*:*:*:*:*:*:*
vendors:
  - Trigger.dev
products:
  - Trigger.dev (< 4.5.2)
cves:
  - id: CVE-2026-85651
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85651
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Trigger.dev to 4.5.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85651 resolution requires version 4.5.2
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 4.5.2
      owner: IT Operations
      addresses: CVE-2026-85651
      evidence: NVD vulnerability disclosure
---

Trigger.dev versions before 4.5.2 are affected by an improper authorization vulnerability in the platform's run replay functionality. The flaw stems from a failure to correctly validate environment membership when a user initiates a replay operation. An authenticated attacker can exploit this weakness to inject task runs into environments or organizations they do not belong to. 

This vulnerability allows for unauthorized resource consumption and the potential to pollute the run history logs of victim projects. Because the replay mechanism executes under the context of the target environment, it could lead to sensitive data processing or unintended side effects if the replayed task logic interacts with external systems configured in the target environment. Organizations using Trigger.dev should prioritize updating to version 4.5.2 or later to ensure that cross-environment replay operations are properly restricted.

## Impact

Successful exploitation allows attackers to manipulate task execution flows across organizational boundaries. The impact includes unauthorized consumption of compute resources, potential injection of malicious task inputs into victim workflows, and degradation of log integrity. This vulnerability affects all self-hosted and cloud-managed instances of Trigger.dev running versions below 4.5.2.

## Recommendation

* Upgrade all Trigger.dev deployments to version 4.5.2 or later to resolve the authorization logic error associated with CVE-2026-85651.
* Audit application logs for abnormal "replay" API calls originating from authenticated users that reference unexpected organization or environment identifiers.
