---
brief_id: brief-2026-11-10-gcc-shell-execution
event_id: brief-2026-11-10-gcc-shell-execution
revision: 1
activity_at: "2026-11-10T02:37:58Z"
title: 'Linux: GCC Compiler Shell Execution'
slug: 2026-11-gcc-shell-execution
description: The GCC, C89, and C99 compilers can be leveraged to execute arbitrary shell commands via the wrapper functionality, a technique often used for privilege escalation or sandbox escapes.
date: "2026-11-10T02:37:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - linux
  - privilege-escalation
  - living-off-the-land
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
    confidence_band: high
references:
  - https://gtfobins.github.io/gtfobins/gcc/#shell
  - https://gtfobins.github.io/gtfobins/c89/#shell
  - https://gtfobins.github.io/gtfobins/c99/#shell
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml
rules:
  - title: Detect GCC, C89, or C99 Wrapper Shell Execution
    description: Detects the use of the gcc, c89, or c99 utility with the -wrapper flag to execute a shell binary
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify GCC wrapper misuse
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source material
  mitigation_plan:
    - priority: medium_term
      action: Remove or restrict access to GCC, C89, and C99 on production systems where code compilation is not a core requirement
      owner: IT Operations
      addresses: Linux compiler wrapper abuse
      evidence: GTFOBins security guidance
---

The gcc, c89, and c99 utilities contain functionality that allows them to use a wrapper program for compilation. By specifying a shell binary and the -s argument via the -wrapper flag, an attacker can force the compiler to execute the shell. This behavior is documented in GTFOBins and is often utilized by threat actors to break out of restricted shells or execute commands under the context of the compiler process.

## Impact
The exploitation of this feature allows for arbitrary command execution on the host system. This may lead to privilege escalation if the compiler is executed with elevated permissions or within a restricted execution environment.

## Recommendation
- Deploy the provided Sigma rule to detect suspicious use of compiler wrappers targeting shell binaries.
- Review environments where compiler utilities are present to determine if they are required for production operations; restrict access to these binaries on systems where they are not necessary.
- Baseline legitimate usage of the -wrapper flag in your build pipelines to differentiate between authorized builds and malicious command execution attempts.
