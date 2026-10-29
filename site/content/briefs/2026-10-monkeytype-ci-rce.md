---
brief_id: brief-2026-10-29-monkeytype-ci-rce
event_id: brief-2026-10-29-monkeytype-ci-rce
revision: 1
activity_at: "2026-10-29T21:10:06Z"
title: 'Monkeytype: Arbitrary code execution in CI workflow (CVE-2026-118762)'
slug: 2026-10-monkeytype-ci-rce
description: Monkeytype versions prior to 26.43.0 contain a vulnerability in the .github/workflows/fix-formatting.yml CI workflow, which uses the pull_request_target trigger with repository write permissions. An external contributor whose pull request receives the format label can execute arbitrary code, read or exfiltrate the GITHUB_TOKEN, and modify repository content.
date: "2026-10-29T21:10:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:monkeytype:monkeytype:*:*:*:*:*:*:*:*
vendors:
  - Monkeytype
products:
  - Monkeytype (< 26.43.0)
cves:
  - id: CVE-2026-118762
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118762
---

The Monkeytype repository CI workflow, specifically .github/workflows/fix-formatting.yml, is vulnerable to arbitrary code execution. Prior to version 26.43.0, the workflow runs on pull_request_target with write permissions and installs dependencies from fork-controlled files. Because actions/checkout persists the GITHUB_TOKEN while untrusted code executes, attackers can exfiltrate the token or perform unauthorized repository actions. This issue affects the CI pipeline, not the Monkeytype application or user data.
