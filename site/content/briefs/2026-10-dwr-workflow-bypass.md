---
title: Unauthenticated Workflow Rule Execution via DWR Request Chaining
slug: 2026-10-dwr-workflow-bypass
description: An unauthenticated vulnerability in DWR request processing allows attackers to execute arbitrary workflow rules by chaining method calls.
date: "2026-10-19T18:11:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - web-security
  - cve-2026-107186
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user can send a DWR request with isPasswordUppercase as one call method and the next call method can be set to a run workflow rule.
    confidence_band: high
cves:
  - id: CVE-2026-107186
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107186
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Scan web logs for DWR batch requests containing high-risk workflow rule function names
      owner: SOC
      due: 24h
      evidence: Vulnerability involves chaining method calls in DWR.
  hunt_leads:
    - lead: Identify DWR gateways receiving calls to sensitive workflow functions from unauthenticated sessions
      technique_id: T1190
      data_needed:
        - Web server access logs with DWR method call parameters
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated access to workflow execution.
---

CVE-2026-107186 is a critical authentication bypass vulnerability affecting Direct Web Remoting (DWR) implementations. An unauthenticated attacker can exploit the way the application processes multiple method calls within a single DWR request. By crafting a request that specifies 'isPasswordUppercase' as the initial call method followed by a second, unauthorized method intended for workflow rule execution, the attacker can force the backend to perform administrative actions. This flaw allows for unauthorized workflow execution without requiring valid credentials. Because this manipulation occurs at the application request level, it bypasses standard session validation logic. The impact is significant as it provides a pathway for unauthenticated remote code execution or business logic manipulation, depending on the capabilities of the accessible workflow rules.

## Attack Chain

1. Attacker identifies an internet-facing endpoint utilizing the DWR framework for AJAX remoting.
2. Attacker prepares a DWR-formatted HTTP POST request targeting the application remoting gateway.
3. Attacker crafts a batch request containing multiple call methods.
4. The first method is set to 'isPasswordUppercase', which the application processes as an unauthenticated or public method.
5. The second call method is set to an administrative workflow rule execution function.
6. The backend application fails to validate authentication status for the subsequent chained method call.
7. The application executes the requested workflow rule with the context of the internal system.
8. Attacker achieves unauthorized execution of business logic or administrative functions.

## Impact

Successful exploitation allows an unauthenticated remote attacker to execute arbitrary workflow rules. This can lead to unauthorized modification of business data, elevation of privileges, or the execution of system-level commands, depending on the configured workflow rules. The impact is assessed as high given the potential for complete compromise of application integrity.

## Recommendation

1. Audit web server and application logs for DWR requests containing chained method calls.
2. Implement strict input validation on all DWR gateways to ensure that chained calls are authenticated per-method, rather than inheriting authentication context from a previous call.
3. Restrict access to administrative or sensitive workflow rule execution endpoints to ensure they are not accessible via standard remoting gateways.
