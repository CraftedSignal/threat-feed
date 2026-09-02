---
title: Authentication Bypass in NGINX JavaScript and QuickJS Engines
slug: 2026-09-nginx-auth-bypass
description: An authentication bypass flaw in NGINX JavaScript (njs) and QuickJS (qjs) engines allows unauthenticated attackers to trigger a fail-open state in access control logic, potentially granting unauthorized access to protected resources.
date: "2026-09-02T17:15:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:nginx_javascript:*:*:*:*:*:*:*:*
vendors:
  - F5
products:
  - NGINX JavaScript
  - QuickJS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this vulnerability by sending a crafted HTTP request that triggers an error condition in the access validation logic.
    confidence_band: high
cves:
  - id: CVE-2026-18329
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18329
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review NGINX configurations for use of the js_access handler
      owner: SOC
      due: 48h
      evidence: Source document identifies js_access handler as the vulnerable component
  hunt_leads:
    - lead: Analyze web server logs for high frequencies of 500-series errors originating from js_access handler modules
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation relies on triggering an exception within the access validation logic
  mitigation_plan:
    - priority: immediate
      action: Review and harden JavaScript access control logic to ensure failures result in access denial rather than success
      owner: IT Operations
      addresses: CVE-2026-18329
      evidence: The vulnerability is triggered by exceptions during asynchronous access-control evaluation
---

The NGINX JavaScript (njs) and QuickJS (qjs) engines contain a vulnerability involving the js_access handler during asynchronous request body processing. When an exception occurs during the asynchronous access-control evaluation phase - specifically before the handler can return an explicit access denial - the engine may fail open. This misconfiguration in the access validation logic permits the request to proceed to downstream resources despite failing security checks. 

An unauthenticated remote attacker can exploit this condition by sending a crafted HTTP request designed to trigger an error within the access-control JavaScript logic. This results in an authorization bypass, potentially allowing access to protected endpoints that should have been restricted. This vulnerability exists within the data plane, impacting any application relying on the njs or qjs access control handlers for security enforcement.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass security controls defined within the js_access handler. This can result in unauthorized access to sensitive application data or protected administrative functions. As this is a data plane issue affecting request processing, it does not involve exposure of the server control plane but directly undermines the security posture of the web application.

## Recommendation

- Identify all instances of NGINX utilizing the `js_access` handler for security controls.
- Audit JavaScript access control logic to ensure that error conditions do not result in a default-allow state.
- Monitor web server error logs for unexpected exceptions occurring within JavaScript access handlers, which may indicate exploitation attempts.
- Apply patches provided by the software vendor once available for NGINX and affected distributions.
