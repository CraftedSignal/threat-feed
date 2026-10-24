---
brief_id: brief-2026-10-24-system-linq-dynamic-core-rce
event_id: brief-2026-10-24-system-linq-dynamic-core-rce
revision: 1
activity_at: "2026-10-24T21:31:16Z"
title: 'System.Linq.Dynamic.Core: Remote Code Execution (CVE-2023-32571)'
slug: 2026-10-system-linq-dynamic-core-rce
description: CVE-2023-32571 is a critical remote code execution vulnerability in System.Linq.Dynamic.Core affecting versions 1.0.7.10 through 1.2.25, triggered by the parsing of untrusted input in LINQ query methods.
date: "2026-10-24T21:31:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation for application inventory
cpes:
  - cpe:2.3:a:zzzprojects:system.linq.dynamic.core:*:*:*:*:*:*:*:*
  - cpe:2.3:a:dynamic-linq:linq:*:*:*:*:*:*:*:*
vendors:
  - zzzprojects
products:
  - System.Linq.Dynamic.Core (1.0.7.10 - 1.2.25)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: This vulnerability allows attackers to execute arbitrary code and commands when untrusted input to methods including Where, Select, OrderBy is parsed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: 'The tool supports two modes: AssemblyLoad (Mode 0): Load and execute a custom .NET assembly'
    confidence_band: high
cves:
  - id: CVE-2023-32571
    cvss: 9.8
    epss: 0.34904
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-32571
  - https://github.com/zzzprojects/System.Linq.Dynamic.Core
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SECTEX-CVE-2023-32571&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Patch System.Linq.Dynamic.Core to 1.3.0 or later
      owner: AppSec
      due: 24h
      evidence: Vulnerability allows RCE via untrusted input.
  hunt_leads:
    - lead: Monitor web application server logs for anomalous execution patterns in query parameters that invoke LINQ filtering or sorting
      technique_id: T1059
      data_needed:
        - Web application logs
        - Endpoint process execution logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers target Where, Select, and OrderBy methods with untrusted input.
  mitigation_plan:
    - priority: immediate
      action: Upgrade System.Linq.Dynamic.Core to version > 1.2.25
      owner: IT Operations
      addresses: CVE-2023-32571
      evidence: Affected versions are 1.0.7.10 to 1.2.25.
---

CVE-2023-32571 is a remote code execution vulnerability in the System.Linq.Dynamic.Core library. The flaw exists in the way the library parses untrusted input within specific LINQ methods, including Where, Select, and OrderBy. Successful exploitation allows for arbitrary assembly loading or direct system command execution. A public proof-of-concept exploit is available, demonstrating both assembly injection and direct process spawning.

## Impact

The vulnerability allows unauthenticated, remote attackers to achieve full remote code execution on the underlying host. The CVSS score is 9.8 (Critical), reflecting the ability to achieve high levels of confidentiality, integrity, and availability impact without requiring user interaction or privileges.

## Recommendation

1. Inventory applications using the System.Linq.Dynamic.Core library to identify instances running versions within the 1.0.7.10 to 1.2.25 range.
2. Update the library dependency to a version beyond 1.2.25 to remediate the vulnerability.
3. Implement strict input validation for all data passed to LINQ query methods if immediate patching is not possible.
