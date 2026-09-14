---
title: CVE-2026-91145 Expression Injection in Activiti
slug: 2026-09-activiti-expression-injection
description: Activiti through 7.1.0.M6 contains an expression injection vulnerability in process variables that allows unauthenticated method invocation on application beans during mail task execution.
date: "2026-09-14T23:36:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:alfresco:activiti:*:*:*:*:*:*:*:*
tags:
  - expression-injection
  - vulnerability
vendors:
  - Alfresco
products:
  - Activiti (<= 7.1.0.M6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: 'Attackers can inject expressions beginning with #{ that are stored and later evaluated in the full Spring context when a mail task uses variable-backed body fields, enabling method invocation on application beans.'
    confidence_band: high
cves:
  - id: CVE-2026-91145
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91145
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Activiti software to the version addressing CVE-2026-91145
      owner: IT Operations
      due: 48h
      evidence: Source reporting vulnerability in versions through 7.1.0.M6
  hunt_leads:
    - lead: 'Search logs for process variable submissions containing #{ '
      technique_id: T1059.007
      data_needed:
        - Web application request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: 'Attacker injects expressions starting with #{'
  mitigation_plan:
    - priority: immediate
      action: Sanitize process variable input to reject hash-brace expressions
      owner: IT Operations
      addresses: CVE-2026-91145
      evidence: Source documentation of injection mechanism
---

Activiti through 7.1.0.M6 contains a critical vulnerability where the engine fails to properly validate hash-brace deferred expressions provided in process variables. This flaw allows an attacker to bypass existing expression filtering mechanisms. An attacker can inject malicious SpEL (Spring Expression Language) expressions starting with the "#{ " sequence into process variables. These variables are persisted by the application and later evaluated within the full Spring application context whenever a mail task is triggered that utilizes variable-backed body fields. Successful exploitation allows for unauthorized method invocation on application beans, potentially leading to arbitrary code execution or unauthorized access to sensitive application data. Defenders should focus on identifying inputs that contain the "#{" sequence and monitoring for unexpected Spring bean method invocations during process engine execution.

## Impact

Successful exploitation of CVE-2026-91145 allows remote attackers to execute arbitrary methods within the Spring application context. This could result in full application compromise, unauthorized data exfiltration, or modification of business processes managed by the Activiti engine. Organizations using affected versions of Activiti to manage sensitive workflows are at high risk of internal unauthorized command or function execution.

## Recommendation

1. Upgrade to a version of Activiti that provides a security patch for CVE-2026-91145.
2. Implement strict input validation on all process variables, specifically looking for and sanitizing the "#{ " pattern before the data reaches the persistence layer.
3. Monitor web server logs for HTTP requests containing the "#{" sequence, which may indicate an attempt to inject malicious expressions into process variables.
4. Review and restrict access to the Activiti management interface to prevent unauthorized process variable modification.
