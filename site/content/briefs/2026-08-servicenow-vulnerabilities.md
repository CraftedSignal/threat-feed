---
title: Multiple Vulnerabilities in ServiceNow Now Platform and AI Platform
slug: 2026-08-servicenow-vulnerabilities
description: ServiceNow Now Platform and AI Platform are vulnerable to multiple flaws enabling arbitrary code execution, privilege escalation, and SQL injection, risking full environment compromise.
date: "2026-08-28T09:10:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - service-now
  - cloud-security
  - informational
vendors:
  - ServiceNow
products:
  - Now Platform
  - AI Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit multiple vulnerabilities in ServiceNow Now Platform and ServiceNow AI Platform to perform SQL injection attacks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit multiple vulnerabilities to execute arbitrary program code.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can exploit multiple vulnerabilities to gain elevated privileges.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3060
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all ServiceNow instances and check for pending security updates.
      owner: IT Operations
      due: 24h
      evidence: ServiceNow platform vulnerability advisory
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches as soon as they become available for the affected versions.
      owner: IT Operations
      addresses: All identified Now Platform and AI Platform instances
      evidence: Standard patching requirement for high-severity vulnerabilities
---

The German Federal Office for Information Security (BSI) has issued an advisory regarding multiple vulnerabilities within the ServiceNow Now Platform and ServiceNow AI Platform. These flaws present significant security risks, potentially allowing remote, unauthenticated, or low-privileged attackers to execute arbitrary code, escalate system privileges, or manipulate the underlying database through SQL injection attacks. Given the enterprise-wide footprint of ServiceNow instances and their access to sensitive organizational data, successful exploitation could lead to total compromise of the application environment. Security teams should prioritize identifying their ServiceNow footprint and applying the latest vendor-supplied patches to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities can result in full remote control of the application, unauthorized access to sensitive data via database manipulation, and lateral movement within the enterprise network through escalated administrative privileges. These platforms are core components in many large-scale IT and HR workflows; their compromise has the potential to impact entire organizational operations.

## Recommendation

- Perform an inventory of all ServiceNow Now Platform and AI Platform instances within the environment.
- Monitor vendor security bulletins via the ServiceNow Support portal for specific patch availability and version guidance.
- Review web application firewall (WAF) logs for anomalous request patterns targeting ServiceNow API endpoints, specifically searching for SQL injection syntax and code execution attempts.
- Restrict access to ServiceNow administrative interfaces to trusted, authenticated management networks.
