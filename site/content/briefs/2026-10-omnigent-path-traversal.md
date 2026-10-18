---
title: Path Traversal Vulnerability in Omnigent
slug: 2026-10-omnigent-path-traversal
description: Omnigent versions 0.3.0 through 0.13.x contain a path traversal vulnerability in bundles.py that allows authenticated attackers to escape restricted workspaces and read or write arbitrary files as the runner user.
date: "2026-10-18T12:21:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:omnigent:omnigent:0.3.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - privilege-escalation
vendors:
  - Omnigent
products:
  - Omnigent (0.3.0 - 0.13.x)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: By manipulating the os_env.cwd parameter within nested sub-agents during bundle uploads, an attacker can read or write arbitrary files on the host system with the privileges of the runner process.
    confidence_band: high
cves:
  - id: CVE-2026-112015
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112015
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Omnigent to version 0.14.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly mandates upgrading to version 0.14.0 or later.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Omnigent 0.14.0
      owner: IT Operations
      addresses: CVE-2026-112015
      evidence: NVD vulnerability details
---

Omnigent versions 0.3.0 through 0.13.x are susceptible to a path traversal vulnerability (CVE-2026-112015) located within the bundles.py component. The flaw arises from insufficient validation of the os_env.cwd parameter assigned to nested sub-agents during bundle processing. Authenticated users can provide specially crafted bundle files that specify an absolute path or use parent directory traversal (e.g., ../) for the sub-agent working directory. This bypasses the intended root-only validation mechanisms within the application. By successfully exploiting this flaw, an attacker gains the ability to perform arbitrary file reads and writes on the host system running the Omnigent agent. Because the agent executes these operations with the privileges of the runner process, successful exploitation can result in full compromise of the local environment, including access to sensitive configuration files, credentials, or the ability to inject malicious code to achieve persistence.

## Impact

The vulnerability poses a high risk to organizations utilizing Omnigent versions 0.3.0 to 0.13.x. Successful exploitation allows for unconstrained file system access, potentially leading to data exfiltration or privilege escalation on systems where the Omnigent runner process is deployed. No specific victim sector is identified, but any environment relying on Omnigent for task orchestration is at risk of unauthorized host-level modifications.

## Recommendation

- Upgrade Omnigent to version 0.14.0 or later to patch the path traversal vulnerability in bundles.py.
- Audit logs for the execution of the Omnigent runner process to identify unexpected file access patterns outside of the designated workspace directories.
- Apply the principle of least privilege to the service accounts executing Omnigent runners to limit the impact of potential file system writes.
