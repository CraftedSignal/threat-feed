---
brief_id: brief-2026-10-22-nbconvert-traversal
event_id: brief-2026-10-22-nbconvert-traversal
revision: 1
activity_at: "2026-10-22T20:03:31Z"
title: 'Jupyter nbconvert: Arbitrary file write via path traversal (CVE-2026-114140)'
slug: 2026-10-nbconvert-traversal
description: Jupyter nbconvert versions up to 7.17.1 are vulnerable to an arbitrary file write attack via path traversal in malicious notebook cell metadata, allowing execution of arbitrary file writes when exporting to specific formats.
date: "2026-10-22T20:03:31Z"
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
  validation_status: Source verified against GHSA advisory.
cpes:
  - cpe:2.3:a:jupyter:nbconvert:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - arbitrary-file-write
  - cve-2026-114140
  - supply-chain
vendors:
  - Jupyter
products:
  - nbconvert (<= 7.17.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: If a victim runs nbconvert on a malicious ipynb file, it can create some files with arbitrary data in arbitrary locations, i.e. override authorized_keys.
    confidence_band: high
cves:
  - id: CVE-2026-114140
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-pjvx-prjx-h659
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114140
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade nbconvert to version 7.17.2 or later across all environments.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability fixed in 7.17.2.
  mitigation_plan:
    - priority: immediate
      action: Upgrade nbconvert to version 7.17.2
      owner: IT Operations
      addresses: CVE-2026-114140
      evidence: Fixed in 7.17.2
---

Jupyter nbconvert contains an arbitrary file write vulnerability (CVE-2026-114140) affecting versions 5.4.0 through 7.17.1. The flaw resides in the `ExtractOutputPreprocessor` component within `extractoutput.py`. When exporting notebooks to Markdown, LaTeX, reStructuredText (RST), or AsciiDoc, the application fails to sanitize the `filename` attribute within cell output metadata. An attacker can use path traversal sequences (e.g., ../) in this metadata to write files outside of the intended output directory.

## Impact

An attacker can write files to arbitrary locations on the host system where the nbconvert process is running. This can lead to the overwriting of sensitive configuration files, such as SSH `authorized_keys`, potentially resulting in full system compromise.

## Recommendation

- Upgrade nbconvert to version 7.17.2 or later immediately.
- Review environments where nbconvert is utilized to process untrusted notebook files.
- Apply the principle of least privilege by running conversion processes within isolated containers or restricted service accounts that lack write access to sensitive system directories.
