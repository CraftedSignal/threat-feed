---
title: Authentication Bypass and SSRF in FastChat /register_worker Endpoint
slug: 2026-09-fastchat-auth-bypass
description: An authentication bypass vulnerability in FastChat allows unauthenticated attackers to register arbitrary workers, enabling server-side request forgery and the interception of model prompts and responses.
date: "2026-09-04T15:26:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:fastchat:fastchat:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - authentication-bypass
vendors:
  - FastChat
products:
  - FastChat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: FastChat contains an authentication bypass vulnerability in the /register_worker endpoint that allows unauthenticated attackers to register arbitrary worker addresses.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can register malicious workers under victim model names to intercept user prompts, images, and responses.
    confidence_band: high
cves:
  - id: CVE-2026-85695
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85695
rules:
  - title: Detect CVE-2026-85695 Exploitation - Unauthorized Registration of FastChat Workers
    description: Detects potential exploitation of the FastChat /register_worker endpoint from unexpected sources.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for unauthorized registrations to the /register_worker endpoint.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms authentication bypass allows arbitrary worker registration.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the FastChat controller /register_worker endpoint to known internal IP ranges only.
      owner: IT Operations
      addresses: CVE-2026-85695
      evidence: Vulnerability allows unauthenticated registration from any remote source.
---

FastChat is vulnerable to an authentication bypass within its /register_worker endpoint, tracked as CVE-2026-85695. This flaw allows unauthenticated remote attackers to register malicious worker nodes to the FastChat controller without proper authorization. By registering these arbitrary worker addresses, an attacker can manipulate the worker mesh, perform server-side request forgery (SSRF) against internal services reachable from the controller, and intercept sensitive data. Specifically, malicious workers can be configured to process requests intended for legitimate models, allowing the attacker to capture user prompts, uploaded images, and model responses. This poses a severe risk to confidentiality and integrity within distributed LLM infrastructure, as the attacker effectively becomes a man-in-the-middle for model interactions.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.4, reflecting the critical nature of the authentication bypass. Successful exploitation allows for the interception of sensitive AI prompts and responses, as well as the potential for unauthorized scanning or exploitation of internal network resources via SSRF. Organizations relying on FastChat for distributed model serving are at risk of data exfiltration and unauthorized access to internal infrastructure.

## Recommendation

Prioritize the identification of internet-facing FastChat controller instances and ensure they are patched to the latest version. Monitor web server logs for suspicious POST requests to the /register_worker endpoint originating from unauthorized or unexpected IP addresses.
