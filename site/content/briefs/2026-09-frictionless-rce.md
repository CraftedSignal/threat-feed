---
title: OS Command Injection in Frictionless Data Package Explorer
slug: 2026-09-frictionless-rce
description: Frictionless Framework versions up to 5.20.0rc1 contain an OS command injection vulnerability in the explore console, allowing arbitrary command execution via crafted datapackage.json files.
date: "2026-09-23T18:44:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:frictionless:frictionless:*:*:*:*:*:*:*:*
vendors:
  - Frictionless
products:
  - Frictionless (<= 5.20.0rc1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can place shell metacharacters in resource path values within a datapackage.json descriptor, which are passed unsanitized to os.system.
    confidence_band: high
cves:
  - id: CVE-2026-93349
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93349
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Frictionless framework to version 5.20.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-93349 mitigation
  mitigation_plan:
    - priority: immediate
      action: Restrict execution of 'frictionless explore' on untrusted or external JSON descriptors
      owner: Security Operations
      addresses: CVE-2026-93349
      evidence: Source advisory
---

Frictionless Framework, a data processing and validation library, is susceptible to an OS command injection vulnerability identified as CVE-2026-93349. This flaw exists within the "explore" console command, which is used to inspect Data Packages. An attacker can craft a malicious `datapackage.json` descriptor file containing shell metacharacters within the resource path values. 

When a user executes the `frictionless explore` command against this untrusted descriptor, the application passes the unsanitized path values to the `os.system` function. This results in the execution of arbitrary commands with the privileges of the user who initiated the explore process. This vulnerability affects all versions of Frictionless up to and including 5.20.0rc1 and represents a significant risk to data scientists and developers who may pull and inspect untrusted data packages from external repositories.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running the Frictionless CLI. This could lead to full system compromise, data exfiltration, or the installation of persistent malicious software on the host machine. The vulnerability impacts any environment where users utilize the Frictionless framework to analyze or validate externally sourced Data Packages.

## Recommendation

* Upgrade to a version of Frictionless released after 5.20.0rc1 that addresses CVE-2026-93349.
* Avoid using the `frictionless explore` command on untrusted or unknown `datapackage.json` files until the software is patched.
* Audit environments where the Frictionless CLI is utilized to determine exposure and ensure users are aware of the risks associated with processing untrusted package descriptors.
