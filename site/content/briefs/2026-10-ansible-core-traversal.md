---
title: Arbitrary File Write in ansible-core via Malicious Collection Installation
slug: 2026-10-ansible-core-traversal
description: A path traversal vulnerability in ansible-core allows attackers to execute arbitrary code on a control node by distributing a crafted collection tarball that bypasses symlink validation.
date: "2026-10-09T00:27:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:ansible_engine:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:ansible_tower:3.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - code-execution
  - path-traversal
vendors:
  - Red Hat
products:
  - ansible-core (< 2.9.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows an attacker who can get a victim to install a malicious collection to overwrite arbitrary files with the privileges of the user running ansible-galaxy, leading to code execution on the control node.
    confidence_band: high
cves:
  - id: CVE-2026-89091
    cvss: 8.8
  - id: CVE-2020-10691
    cvss: 5.2
    epss: 0.00353
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89091
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade ansible-core to 2.9.7 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-89091 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict dependency and collection vetting processes for all automation workflows.
      owner: Security Engineering
      addresses: CVE-2026-89091
      evidence: Exploitation relies on the installation of malicious third-party collections.
---

CVE-2026-89091 describes a critical path traversal vulnerability within the ansible-core archive extraction process. During the execution of 'ansible-galaxy collection install', the system performs lexical path normalization via 'os.path.abspath' but fails to resolve symbolic links or conduct containment checks before processing directory members within a tarball. An attacker can construct a malicious collection containing chained symlink directory entries that point outside the intended installation path. When an unsuspecting user installs the collection, the extraction process follows these symlinks and overwrites arbitrary files on the local filesystem. Because 'ansible-galaxy' typically runs with the permissions of the invoking user, this flaw enables arbitrary file write, which can be leveraged to achieve code execution on the control node. This vulnerability represents a regression or bypass of the mitigations previously introduced for CVE-2020-10691. Organizations should prioritize updating ansible-core to the vendor-patched release.

## Impact

Successful exploitation allows a malicious actor to overwrite critical files on the system running 'ansible-galaxy'. If the victim is a privileged user or service account, the attacker can achieve persistent code execution on the control node, potentially leading to full compromise of the automation environment and subsequent lateral movement across the infrastructure managed by Ansible.

## Recommendation

* Patch ansible-core to the latest version provided by Red Hat that addresses CVE-2026-89091.
* Audit build pipelines and CI/CD runners to ensure only collections from trusted, verified sources are installed.
* Restrict the permissions of accounts authorized to run 'ansible-galaxy collection install' to minimize the impact of potential file overwrite attacks.
