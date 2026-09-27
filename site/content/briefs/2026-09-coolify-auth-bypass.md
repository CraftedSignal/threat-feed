---
title: Authentication Bypass in Coolify GitHub App Setup Handler
slug: 2026-09-coolify-auth-bypass
description: An unauthenticated remote code execution vulnerability (CVE-2026-100746) in Coolify versions 4.1.0 and earlier allows attackers to bypass authentication via the GitHub App setup flow.
date: "2026-09-27T05:03:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coollabsio:coolify:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - authentication-bypass
vendors:
  - coollabsio
products:
  - Coolify (<= 4.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-100746
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100746
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all Coolify instances to version 4.1.1 or later.
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 4.1.1 mitigates this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch Coolify to version 4.1.1
      owner: IT Operations
      addresses: CVE-2026-100746
      evidence: Upgrading to version 4.1.1 mitigates this issue.
---

CVE-2026-100746 identifies a critical missing authentication vulnerability in Coolify versions up to and including 4.1.0. The vulnerability resides within the GitHub App Setup Handler, specifically affecting the `Github::redirect` function located in `/webhooks/source/github/redirect`. An attacker can manipulate the `state` argument within the GitHub authentication redirect flow to bypass authentication mechanisms entirely. Given that public proof-of-concept exploit material is available, this vulnerability poses an immediate risk of unauthorized access to self-hosted Coolify instances. Defenders should treat this as a high-priority update task, as exploitation is performed remotely without requiring existing credentials.

## Impact

Successful exploitation allows an unauthenticated remote attacker to bypass authentication controls, potentially gaining administrative control over the Coolify instance. This could lead to full system compromise, deployment of malicious containers, and unauthorized access to managed infrastructure. All users running Coolify 4.1.0 or earlier are at risk.

## Recommendation

* Upgrade Coolify instances to version 4.1.1 or later immediately to patch CVE-2026-100746.
* Review web access logs for anomalous POST or GET requests to the endpoint `/webhooks/source/github/redirect` where the `state` parameter appears unusually formatted or is used to facilitate unexpected redirection.
* Verify that any Coolify instance exposed to the internet is restricted by network-level controls (e.g., VPN or IP allowlisting) while the upgrade process is underway.
