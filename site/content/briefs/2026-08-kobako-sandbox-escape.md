---
title: Kobako Sandbox Escape via Ruby Method Injection
slug: 2026-08-kobako-sandbox-escape
description: A vulnerability in the Kobako gem allows guest mruby scripts to escape the sandbox and execute arbitrary Ruby code on the host process via improper method dispatch.
date: "2026-08-18T20:56:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
products:
  - kobako (0.1.0-0.9.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: Ruby'
    evidence: A guest call equivalent to Service.send(:eval, <arbitrary host ruby>) executes in the host process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7pwq-q9jf-539h
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Kobako to version 0.9.1 to address CVE-2026-55107
      owner: IT Operations
      due: 24h
      evidence: Fixed in 0.9.1. The dispatcher now rejects any method whose resolved owner is a core/meta module.
  mitigation_plan:
    - priority: immediate
      action: Unbind host Service objects from sandboxes handling untrusted scripts
      owner: IT Operations
      addresses: CVE-2026-55107
      evidence: Until you can upgrade, do not bind any host Service object into a sandbox that runs untrusted scripts.
---

The Kobako Ruby gem (versions 0.1.0 through 0.9.0) contains a critical sandbox escape vulnerability, identified as CVE-2026-55107. The vulnerability exists within the transport dispatcher, which facilitates communication between guest mruby scripts and host-defined "Service" objects. The dispatcher incorrectly utilized `public_send` to process method calls from the guest, allowing the invocation of any method accessible to the bound object.

Because `public_send` does not restrict the target method to those explicitly defined by the Service, a guest script can invoke ambient reflection methods such as `send`, `__send__`, or `public_send`. By pivoting through these methods, an attacker can access sensitive `Kernel` methods, specifically `eval`, to execute arbitrary Ruby code within the host process. This bypasses the primary security guarantee of the Kobako library. The issue was resolved in version 0.9.1 by implementing a blocklist that prevents the invocation of methods belonging to core Ruby modules like `Kernel`, `Object`, and `Module`.

## Impact

Successful exploitation results in a full sandbox escape, granting an attacker the ability to execute arbitrary Ruby code within the context of the host process. This can lead to unauthorized access to host memory, modification of host state, or the execution of arbitrary system commands, depending on the privileges of the Ruby process. All deployments running untrusted mruby scripts using Kobako versions 0.9.0 and earlier are affected.

## Recommendation

- Upgrade to Kobako version 0.9.1 immediately to implement the required method invocation filtering.
- If immediate patching is not feasible, unbind all host "Service" objects from sandboxes processing untrusted scripts until the upgrade is performed.
- Audit existing mruby script execution environments for signs of unusual method invocation patterns if the host process is exposed to untrusted input.
