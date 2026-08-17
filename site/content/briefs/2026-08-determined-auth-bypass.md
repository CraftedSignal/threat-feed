---
title: Missing Authorization in Determined API Endpoints (CVE-2026-75109)
slug: 2026-08-determined-auth-bypass
description: Determined AI's Determined platform fails to authorize API requests for generic task management, allowing authenticated attackers to disrupt workloads by terminating or pausing tasks owned by other users.
date: "2026-08-17T22:51:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - access-control
  - cloud
vendors:
  - Determined AI
products:
  - Determined (<= 0.38.1)
cves:
  - id: CVE-2026-75109
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75109
  - https://www.vulncheck.com/advisories/determined-missing-authorization-check-on-generic-task-endpoints
  - https://github.com/determined-ai/determined/issues/10270
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Determined platform to version 0.38.2
      owner: IT Operations
      due: 48h
      evidence: Vendor fix release
  hunt_leads:
    - lead: Search API logs for high frequency of task state modification commands (kill/pause/unpause) from non-privileged users
      technique_id: T1068
      data_needed:
        - Web application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Authorization bypass behavior
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-75109
      owner: IT Operations
      addresses: CVE-2026-75109
      evidence: NVD advisory
---

Determined AI's Determined platform (versions up to and including 0.38.1) contains a critical missing authorization vulnerability (CVE-2026-75109) within its generic task API handlers. Specifically, the endpoints responsible for killing, pausing, and unpausing tasks do not perform checks to ensure the requester is the owner of the task or has appropriate administrative permissions. An authenticated user within the environment can leverage this flaw to manipulate the execution state of tasks belonging to other users. This vulnerability is documented as CWE-862 and poses a significant risk to organizations utilizing Determined for shared compute and machine learning model training workloads, as it enables unauthorized service disruption and potential operational sabotage.

## Impact

The vulnerability allows for the unauthorized disruption of active workloads within the Determined platform. If exploited, an authenticated attacker can terminate, pause, or unpause arbitrary tasks, directly impacting production model training, research workflows, and resource allocation. This can lead to significant delays in data science operations, loss of compute-intensive task progress, and degradation of platform availability.

## Recommendation

* Upgrade Determined to version 0.38.2 or later immediately to apply the required authorization checks in the API handlers.
* Review web server or API gateway access logs for abnormal volumes of requests to the generic task API endpoints (typically mapped to `kill`, `pause`, or `unpause` operations) originating from users who should not have administrative control over those task IDs.
* Restrict platform access to trusted users and enforce the principle of least privilege for API usage until the patch is applied.
