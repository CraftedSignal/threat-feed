---
brief_id: brief-2026-10-21-gitpython-path-traversal
event_id: brief-2026-10-21-gitpython-path-traversal
revision: 2
activity_at: "2026-10-22T20:01:32Z"
revision_history:
  - revision: 2
    at: "2026-10-22T20:01:32Z"
    checksum: sha256:e95c29fc17c9f7c9cfcec1e188b8ef7e8e253b362005975245068a55859a9644
    summary: poc_available
    changed_fields:
      - affected_vendors
      - cpes
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-83vg-56qc-22m7
title: 'GitPython: Path traversal and arbitrary code execution (CVE-2026-114145)'
slug: 2026-10-gitpython-path-traversal
description: GitPython versions prior to 3.2.1 are vulnerable to a path traversal flaw in the create_submodule() function, which allows an attacker-influenced submodule path to lead to the execution of a planted post-checkout hook.
date: "2026-10-21T21:41:42Z"
lastmod: "2026-10-22T20:00:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:gitpython:gitpython:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - GitPython
products:
  - GitPython (< 3.2.1)
cves:
  - id: CVE-2026-114145
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114145
  - https://github.com/advisories/GHSA-83vg-56qc-22m7
updates:
  - at: "2026-10-22T20:00:35Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-83vg-56qc-22m7
---

GitPython prior to 3.2.1 contains a vulnerability in create_submodule() in git/objects/submodule/base.py. The function accepts an attacker-influenced submodule path (such as .git/hooks) and invokes _clone_repo() before rejecting the destination. In 3.1.x, the call succeeds silently. In 3.2.0 and later affected revisions, a check in git/index/base.py raises a ValueError only after the clone has written to disk and does not remove the planted file. This allows an attacker to place an executable post-checkout hook that a later Git operation executes. Exploitation requires an application to accept an untrusted submodule path and a clone destination that is sufficiently empty. This issue is fixed in version 3.2.1.
