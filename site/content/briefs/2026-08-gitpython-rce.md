---
title: Remote Code Execution in GitPython via Git Config Injection
slug: 2026-08-gitpython-rce
description: GitPython versions before 3.1.59 contain a vulnerability where improper sanitization of multi-line configuration values allows attackers to inject arbitrary git directives, leading to remote code execution.
date: "2026-08-25T04:05:22Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft config files with embedded newlines that become live git directives after any unrelated GitPython config write, enabling arbitrary code execution via hook invocation.
    confidence_band: high
cves:
  - id: CVE-2026-78676
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78676
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-284h-m62q-gf8w
  - https://www.vulncheck.com/advisories/gitpython-before-remote-code-execution-via-config-injection
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Upgrade GitPython dependency to 3.1.59
      owner: Development Teams
      due: 24h
      evidence: GitPython versions before 3.1.59 are affected
  mitigation_plan:
    - priority: immediate
      action: Dependency update
      owner: IT Operations
      addresses: CVE-2026-78676
      evidence: Affected version range identified in NVD
---

GitPython is a Python library used to interact with Git repositories. A critical vulnerability (CVE-2026-78676) exists in versions prior to 3.1.59 due to improper re-serialization of multi-line configuration values during git-config write operations. An attacker can supply a specially crafted configuration value containing embedded newlines. When GitPython performs a write operation on the configuration file, these newlines cause the injected content to be interpreted as new, live git configuration directives. A primary vector involves the injection of a malicious `core.hooksPath`, which directs Git to execute arbitrary code from a location controlled by the attacker whenever a Git hook is triggered. This vulnerability enables unauthenticated remote code execution in environments where GitPython processes untrusted configuration data.

## Attack Chain

1. The attacker provides a malicious, multi-line string intended to be written to a `.git/config` file (e.g., through an application interface using GitPython).
2. The application uses the vulnerable GitPython library to update the repository configuration with the attacker-controlled input.
3. GitPython fails to escape or neutralize the newline characters within the input string during the serialization process.
4. The serialized output is written to the `.git/config` file, effectively terminating the intended configuration key and starting a new directive on the subsequent line.
5. The injected directive, such as `core.hooksPath = /tmp/malicious_hooks_dir`, is successfully written into the configuration file.
6. The system or user triggers a standard Git operation (e.g., `git commit` or `git push`) within the repository.
7. Git reads the corrupted configuration file and executes the malicious scripts located in the attacker-specified hooks directory.
8. Final objective achieved: Remote code execution under the context of the user running the Git operation.

## Impact

The vulnerability carries a CVSS score of 9.8, indicating a critical risk of complete system compromise. Successful exploitation allows for unauthenticated remote code execution, which can lead to data exfiltration, unauthorized access to internal development environments, and the deployment of persistent backdoors within software supply chains. Any system or automated pipeline utilizing GitPython to manage repository configurations with untrusted input is at risk.

## Recommendation

* Upgrade the `GitPython` library to version 3.1.59 or later immediately to address CVE-2026-78676.
* Audit application code that passes user-supplied input to GitPython's configuration write functions.
* Implement strict input validation to ensure configuration values do not contain newline characters or unexpected git directives.
* Review logs for unauthorized modifications to `.git/config` files within critical infrastructure or CI/CD environments.
