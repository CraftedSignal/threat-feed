---
brief_id: brief-2026-11-10-omniagent-bypass
event_id: brief-2026-11-10-omniagent-bypass
revision: 1
activity_at: "2026-11-10T02:04:30Z"
title: 'OmniAgent: ReflexionAgent command injection via find (CVE-2026-125368)'
slug: 2026-11-omniagent-bypass
description: OmniAgent contains an approval bypass vulnerability in the ReflexionAgent._is_safe_bash_command method, allowing prompt-injected agents to execute arbitrary binaries via the find -execdir flag.
date: "2026-11-10T02:04:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:omniagent:omniagent:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - prompt-injection
vendors:
  - OmniAgent
products:
  - OmniAgent (<= 12b98c5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Prompt-injected agents can run find with -execdir to invoke binaries like dd, nc, perl or openssl through an unsandboxed shell
    confidence_band: high
cves:
  - id: CVE-2026-125368
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125368
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit shell execution logs for usage of the find command with the -execdir flag
      owner: Detection Engineering
      due: 48h
      evidence: Vulnerability allows find -execdir to invoke unauthorized binaries
  hunt_leads:
    - lead: Identify shell processes initiated by the OmniAgent service that contain the find utility with the -execdir flag
      technique_id: T1059.004
      data_needed:
        - Process command line logging
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The flaw lies in the failure to inspect -execdir arguments within the agent shell
  mitigation_plan:
    - priority: immediate
      action: Restrict binary path execution permissions for the user account running OmniAgent
      owner: IT Operations
      addresses: CVE-2026-125368
      evidence: Vulnerability allows execution of arbitrary binaries like dd, nc, perl or openssl
---

OmniAgent through commit 12b98c5 contains an approval bypass vulnerability in the ReflexionAgent._is_safe_bash_command function. The component incorrectly validates shell commands by only checking if they start with the 'find' utility, failing to inspect the arguments passed to the '-execdir' flag. This allows an attacker to bypass human-in-the-loop security controls.

## Impact

An attacker can leverage prompt injection to force the agent to execute unauthorized binaries such as 'dd', 'nc', 'perl', or 'openssl' within an unsandboxed shell environment. This results in the potential for arbitrary code execution or unauthorized file modification on the host running the agent.

## Recommendation

* Inventory all instances of OmniAgent running versions up to commit 12b98c5.
* Audit application logs for calls to 'find' that include the '-execdir' argument within agent-managed shell execution environments.
* Implement input validation or restrict binary execution at the OS level for environments hosting OmniAgent to prevent the execution of sensitive binaries like 'nc' or 'dd' by the agent process.
