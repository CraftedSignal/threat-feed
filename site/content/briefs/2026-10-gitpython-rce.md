---
title: Remote Code Execution in GitPython via Unsafe URL Handling
slug: 2026-10-gitpython-rce
description: GitPython versions prior to 3.2.0 contain a remote code execution vulnerability where the Git.ls_remote method improperly handles URLs, allowing arbitrary command execution via malicious remote-helper strings.
date: "2026-10-15T00:33:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gitpython_project:gitpython:*:*:*:*:*:*:*:*
vendors:
  - GitPython
products:
  - GitPython (< 3.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows attackers to run commands because Git.ls_remote forwards URLs without check_unsafe_protocols validation.
    confidence_band: high
cves:
  - id: CVE-2026-110857
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110857
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitPython to version 3.2.0 or later.
      owner: IT Operations
      addresses: CVE-2026-110857
      evidence: GitPython before 3.2.0 contains a remote code execution vulnerability.
---

GitPython versions before 3.2.0 are vulnerable to remote code execution (RCE) and option injection due to insufficient input validation within several key methods. The vulnerability primarily stems from the Git.ls_remote method, which forwards user-provided URLs to the underlying git binary without validating against unsafe protocols. An attacker can leverage this to supply 'ext::' remote-helper URLs, which can be configured to execute arbitrary commands if the system's git environment permits the 'ext' transport protocol. Furthermore, the library's merge_base and IndexFile.move methods fail to sanitize inputs, rendering them susceptible to option injection attacks. This vulnerability poses a significant risk to applications that process untrusted repository URLs or Git-related inputs, potentially allowing unauthorized system access under the context of the service running the GitPython library.

## Impact

Successful exploitation allows remote attackers to execute arbitrary commands on systems running applications that utilize GitPython (< 3.2.0) to process user-provided repository URLs or file operations. This vulnerability affects any environment using the vulnerable library, across Linux, Windows, or macOS, and could lead to full system compromise depending on the privileges of the application process.

## Recommendation

- Upgrade GitPython to version 3.2.0 or later immediately to patch CVE-2026-110857.
- Audit applications utilizing GitPython to identify code paths where user-supplied strings are passed to the 'ls_remote', 'merge_base', or 'move' methods.
- Ensure that the underlying git configuration on production servers has the 'ext' transport protocol disabled or restricted to prevent the exploitation of remote-helper URLs.
