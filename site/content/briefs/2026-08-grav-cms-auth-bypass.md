---
title: Authentication Bypass in Grav CMS scheduler-webhook Plugin
slug: 2026-08-grav-cms-auth-bypass
description: An authentication bypass in the Grav CMS scheduler-webhook plugin allows unauthenticated attackers to trigger pre-configured scheduled jobs via the /scheduler/webhook endpoint.
date: "2026-08-07T19:34:53Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Grav CMS
products:
  - scheduler-webhook
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker who can reach POST /scheduler/webhook can trigger the operator's already-configured scheduled jobs.
    confidence_band: high
cves:
  - id: CVE-2026-11430
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11430
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit Grav CMS configurations for enabled scheduler-webhook plugins
      owner: IT Operations
      due: 48h
      evidence: Source description of required plugin configuration
  mitigation_plan:
    - priority: immediate
      action: Configure webhookToken for all enabled scheduler-webhook instances
      owner: IT Operations
      addresses: CVE-2026-11430
      evidence: Source states that setting a webhookToken prevents the authentication bypass
---

CVE-2026-11430 identifies an authentication bypass vulnerability within the scheduler-webhook plugin for Grav CMS. The flaw originates from a short-circuiting conditional statement in the plugin's token validation logic. When the webhook feature is enabled (via `scheduler.modern.webhook.enabled` set to true) but a `webhookToken` is not explicitly configured, the validation routine is skipped entirely. 

An unauthenticated remote attacker can exploit this by sending a crafted POST request to the `/scheduler/webhook` endpoint. While the attacker cannot inject arbitrary code, they can force the execution of already-configured scheduled jobs, including those that execute system commands. The impact is limited by the existing server configuration, as the attacker can control the execution timing and select which pre-existing job to trigger, but cannot define the initial task payload. This vulnerability is not present in default Grav installations, as it requires the manual installation of the plugin and specific misconfiguration.

## Impact

Successful exploitation allows an unauthenticated attacker to trigger administrative scheduled tasks on the affected server. Depending on the configured jobs, this could lead to unauthorized system command execution, denial of service through resource exhaustion, or the manipulation of application state. The vulnerability affects instances where the scheduler-webhook plugin is enabled without a security token.

## Recommendation

- Immediately audit Grav CMS installations to identify instances where the `scheduler-webhook` plugin is enabled.
- Ensure a strong `webhookToken` is configured for any enabled webhooks to prevent the short-circuiting logic from bypassing validation.
- Review all configured scheduled jobs for the `scheduler-webhook` plugin to ensure they do not perform sensitive operations if triggered by unauthorized parties.
- Monitor web server logs for suspicious POST requests targeting the `/scheduler/webhook` path, particularly those containing the `job` parameter.
