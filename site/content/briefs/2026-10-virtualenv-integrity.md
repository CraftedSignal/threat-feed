---
title: Lack of Integrity Verification in virtualenv Seed Wheel Downloads
slug: 2026-10-virtualenv-integrity
description: The virtualenv library lacks integrity checks for downloaded pip and setuptools seed wheels, enabling potential arbitrary code execution via compromised mirrors or MITM attacks.
date: "2026-10-01T04:20:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pypa:virtualenv:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - vulnerability
  - python
vendors:
  - PyPA
products:
  - virtualenv (<= 21.7.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: A compromised index, a stale mirror, or a MITM'd download could substitute a different wheel under the same distribution/version/filename.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: virtualenv would cache and seed it into every environment created afterward.
    confidence_band: high
cves:
  - id: CVE-2026-102930
references:
  - https://github.com/advisories/GHSA-94p9-xgh2-xp45
  - https://github.com/pypa/virtualenv/pull/3251
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102930
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade virtualenv to 21.7.12 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies vulnerable versions <= 21.7.11.
  mitigation_plan:
    - priority: immediate
      action: Upgrade virtualenv to version > 21.7.11.
      owner: IT Operations
      addresses: CVE-2026-102930
      evidence: GitHub GHSA-94p9-xgh2-xp45 and PR 3251.
---

The Python library virtualenv (versions up to 21.7.11) contains a critical security flaw where seed wheels, specifically pip and setuptools, are not verified for integrity when downloaded via the --download flag or the automatic periodic-update mechanism. While embedded wheels are protected by a hardcoded SHA256, wheels fetched dynamically over the network are trusted implicitly. This vulnerability, tracked as CVE-2026-102930, allows a malicious actor - such as an entity controlling a compromised PyPI mirror, a rogue index server, or an attacker performing a Man-in-the-Middle (MITM) interception - to substitute a legitimate wheel with a malicious one. If successful, virtualenv will cache the compromised wheel and inject it into every future virtual environment created on the affected host, resulting in persistent arbitrary code execution within those environments.

## Impact

Successful exploitation results in arbitrary code execution within any virtual environment created using the compromised virtualenv instance. Because the malicious wheel is cached, the persistence of the compromise is high, affecting all subsequent project setups on the host. This vulnerability is particularly concerning in automated build environments, CI/CD pipelines, and developer workstations that frequently create new virtual environments for Python dependency management.

## Recommendation

Prioritized actions for security and engineering teams:

- Update the virtualenv package to a version containing the fix for CVE-2026-102930 (ensure usage is beyond v21.7.11).
- Audit existing virtualenv installations for suspicious wheel caches located in standard cache directories.
- Implement strict transport security and trusted index configurations for internal Python development pipelines to minimize MITM risks.
- Verify if environments are using private indices, as the security check is currently bypassed when custom indexes (PIP_INDEX_URL, PIP_EXTRA_INDEX_URL) are configured.
