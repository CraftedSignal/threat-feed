---
title: Arbitrary Code Execution in sift.js via Prototype Pollution and $where Operator
slug: 2026-09-sift-js-prototype-pollution
description: The sift.js library version 17.1.3 is vulnerable to arbitrary code execution when processing untrusted input that leverages prototype pollution or malicious $where operator strings to invoke the new Function constructor.
date: "2026-09-04T15:28:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sift:sift:17.1.3:*:*:*:*:*:*:*
tags:
  - vulnerability
  - code-execution
  - prototype-pollution
  - javascript
  - cve-2026-85625
vendors:
  - sift
products:
  - sift (17.1.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The $where operation compiles a string value into a function using new Function unless CSP_ENABLED is set, leading to arbitrary JavaScript code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85625
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85625
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Inventory all applications utilizing sift.js and verify version 17.1.3 usage.
      owner: AppSec
      due: 48h
      evidence: CVE-2026-85625 identifies 17.1.3 as the vulnerable version.
  mitigation_plan:
    - priority: immediate
      action: Set CSP_ENABLED to true in sift.js configurations or upgrade to a patched version.
      owner: IT Operations
      addresses: CVE-2026-85625
      evidence: Source states CSP_ENABLED prevents the use of the new Function constructor.
---

The sift.js library, specifically version 17.1.3, contains a high-severity vulnerability (CVE-2026-85625) due to the use of for...in loops for query key enumeration. By iterating over the object prototype chain, the library inadvertently dispatches matched operator keys, including the sensitive $where operator. Under the default configuration, where CSP_ENABLED is not set, sift utilizes the new Function constructor to execute the string value associated with the $where operator. This allows an attacker who can either perform prototype pollution - injecting a $where property into Object.prototype - or pass a crafted query object containing a malicious $where string, to achieve arbitrary JavaScript execution within the host process. This vulnerability poses a significant risk to Node.js applications that utilize sift.js to filter untrusted user input, as the execution occurs within the context of the running application.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary JavaScript code on the server hosting the affected application. This can lead to full application compromise, unauthorized access to data, and further lateral movement within the environment. Given the widespread use of data filtering libraries in web frameworks, this vulnerability affects any sector utilizing sift.js for query processing without explicit security hardening.

## Recommendation

1. Upgrade sift.js to a version where prototype chain walking is prevented or the $where operator is disabled by default.
2. Implement strict input validation for all query objects passed to the sift library to ensure they do not contain unexpected operator keys.
3. If version upgrading is not immediately possible, explicitly set the CSP_ENABLED configuration to true or define an environment-based mitigation to disable dangerous evaluation patterns in sift.js.
