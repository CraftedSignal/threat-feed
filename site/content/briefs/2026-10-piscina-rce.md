---
title: Prototype Pollution Gadget in Piscina ThreadPool Options
slug: 2026-10-piscina-rce
description: A prototype pollution gadget in the Piscina library allows unauthenticated attackers to execute arbitrary code or manipulate worker environments by injecting properties via Object.prototype.
date: "2026-10-01T20:20:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:piscina_project:piscina:*:*:*:*:*:node.js:*:*
tags:
  - remote-code-execution
  - prototype-pollution
  - supply-chain
products:
  - piscina (< 4.9.4, >= 5.0.0 < 5.3.2, >= 6.0.0-rc.1 < 6.0.0-rc.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1565.001
    technique_name: Stored Data Manipulation
    evidence: A prototype-pollution gadget in ThreadPool.options allows an attacker who can pollute Object.prototype to execute arbitrary code in Piscina worker threads.
    confidence_band: high
cves:
  - id: CVE-2026-102992
    epss: 0.00552
references:
  - https://github.com/advisories/GHSA-67c8-pqhq-4rmx
  - https://github.com/Fcmam5/piscina-pp-poc
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Piscina to version 4.9.4, 5.3.2, or 6.0.0-rc.5
      owner: Application Security
      due: 24h
      evidence: Source advisory specifies fixed versions for impacted branches
  mitigation_plan:
    - priority: immediate
      action: Upgrade piscina to 4.9.4 or later
      owner: IT Operations
      addresses: CVE-2026-102992
      evidence: Source advisory
---

Piscina, a popular Node.js worker pool library, is vulnerable to a prototype pollution gadget that enables remote code execution (RCE) and environment manipulation. The vulnerability (CVE-2026-102992) stems from how the `ThreadPool` class constructs its internal options object. By using object spread syntax (`{ ...kDefaultOptions, ...options }`) on a plain object that inherits from `Object.prototype`, Piscina inadvertently honors properties present in the global prototype if they are not explicitly defined in the options provided to the constructor.

An attacker who can influence the application state to pollute `Object.prototype` can inject malicious configuration values. The most critical vector is the `execArgv` property, which allows an attacker to force worker threads to load an arbitrary module via the `--require` flag upon initialization. Other vectors include the `loadBalancer` function, which can be manipulated to execute arbitrary logic during task scheduling, and the `env` property, which allows for the injection of environment variables into worker processes. This issue persists in Piscina versions < 4.9.4, 5.0.0 through 5.3.1, and 6.0.0-rc.1 through 6.0.0-rc.4.

## Impact

Successful exploitation allows for Remote Code Execution (RCE) within the context of the Node.js worker process. Beyond RCE, the ability to control worker environment variables and task scheduling logic permits an attacker to exfiltrate sensitive process information or disrupt application availability. The vulnerability affects any application using an impacted version of Piscina where an upstream prototype pollution primitive exists.

## Recommendation

* Update the Piscina dependency to version 4.9.4, 5.3.2, or 6.0.0-rc.5 or later.
* Audit the application codebase for existing prototype pollution vulnerabilities in dependencies, as these are required to trigger this gadget.
* Implement security scanning to identify vulnerable versions of Piscina (CVE-2026-102992) within the project's dependency manifest.
