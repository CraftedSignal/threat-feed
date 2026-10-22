---
brief_id: brief-2026-10-22-black-github-action-rce
event_id: brief-2026-10-22-black-github-action-rce
revision: 1
activity_at: "2026-10-22T20:03:39Z"
title: 'Black: GitHub Action remote code execution via pyproject.toml (CVE-2026-114134)'
slug: 2026-10-black-github-action-rce
description: The GitHub Action bundled with Black fails to validate the required-version parameter from pyproject.toml when use_pyproject is enabled, allowing for the execution of untrusted code in the GitHub Actions runner environment.
date: "2026-10-22T20:03:39Z"
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
products:
  - black (< 26.10.1)
cves:
  - id: CVE-2026-114134
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-cg8m-r9f2-5wm2
---

The GitHub Action bundled with Black reads the version from 'tool.black.required-version' when 'use_pyproject' is set to True. This value is not validated and can be used to execute untrusted code in the context of a victim's repository. Successful exploitation requires a victim to use the Black GitHub Action with 'use_pyproject: true', and an attacker to submit a pull request with a modified 'pyproject.toml' file.
