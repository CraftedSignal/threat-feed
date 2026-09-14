---
title: Hard-coded JWT Secret in Crawlab Vulnerability
slug: 2026-09-crawlab-jwt-hardcoded-secret
description: Crawlab versions 0.6.3 and earlier utilize a hard-coded HMAC-SHA256 secret for JWT signing, enabling unauthenticated attackers to forge administrative tokens and achieve remote code execution.
date: "2026-09-14T19:35:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:crawlab:crawlab:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - remote-code-execution
vendors:
  - Crawlab
products:
  - Crawlab (<= 0.6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can forge valid administrator tokens to access administrative APIs.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Crawlab through 0.6.3 uses a hard-coded HMAC-SHA256 secret for JWT token signing.
    confidence_band: high
cves:
  - id: CVE-2026-90945
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90945
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Crawlab to version 0.6.4 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions through 0.6.3 are affected.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Crawlab administrative APIs
      owner: IT Operations
      addresses: CVE-2026-90945
      evidence: API access is required for exploitation of the hard-coded secret.
---

Crawlab versions up to and including 0.6.3 contain a critical vulnerability involving the use of a hard-coded HMAC-SHA256 secret for signing JSON Web Tokens (JWT). Because this secret cannot be overridden via configuration files or environment variables, it remains static across all installations. An unauthenticated attacker with knowledge of this hard-coded secret can construct forged JWTs with administrative claims. By presenting these forged tokens to the application's authentication middleware, an attacker gains unauthorized access to administrative APIs. These APIs include functionality that allows for the scheduling and execution of tasks on worker nodes, effectively leading to unauthorized remote code execution (RCE). This vulnerability poses a severe risk to any environment hosting Crawlab, as it bypasses all standard authentication controls.

## Impact

Successful exploitation allows for full administrative compromise of the Crawlab platform. Attackers can gain unrestricted access to sensitive configuration data, control over scheduled web crawling tasks, and the ability to execute arbitrary code on infrastructure running Crawlab worker nodes. This impact is platform-wide, affecting all deployments using versions 0.6.3 or earlier.

## Recommendation

Prioritized actions for security teams:
- Identify and inventory all Crawlab instances currently running version 0.6.3 or earlier within the environment.
- Prioritize the immediate upgrade of all identified Crawlab instances to the latest available patched version where the JWT secret implementation has been remediated.
- Monitor web server logs for suspicious API requests carrying JWTs, specifically looking for anomalous administrative access patterns originating from unauthorized or external IP addresses.
- Enforce network-level segmentation to restrict access to Crawlab administrative interfaces, ensuring they are not exposed to the public internet.
