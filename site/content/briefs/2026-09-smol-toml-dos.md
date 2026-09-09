---
title: Denial of Service in smol-toml via Malformed TOML
slug: 2026-09-smol-toml-dos
description: The smol-toml library (<= 1.7.0) is vulnerable to a denial-of-service condition (CVE-2026-85730) where malformed TOML input triggers an infinite loop, causing 100% CPU utilization.
date: "2026-09-09T18:51:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - smol-toml (<= 1.7.0)
cves:
  - id: CVE-2026-85730
    epss: 0.0037
references:
  - https://github.com/advisories/GHSA-7w5x-hrqm-74c2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85730
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update smol-toml dependency to v1.7.1 or later
      owner: IT Operations
      due: 48h
      evidence: Version 1.7.1 properly breaks out of the loop and throws the expected TomlError.
  mitigation_plan:
    - priority: immediate
      action: Patch smol-toml to 1.7.1
      owner: IT Operations
      addresses: CVE-2026-85730
      evidence: https://github.com/advisories/GHSA-7w5x-hrqm-74c2
---

The smol-toml library is susceptible to a denial-of-service (DoS) vulnerability, tracked as CVE-2026-85730. The vulnerability resides in the `parse()` function, which fails to correctly handle specific malformed TOML documents. When an array or inline table within a TOML document is followed by a comment that lacks a trailing newline at the end of the file, the parser's internal logic enters an infinite loop. During this loop, the parser incorrectly resets its cursor to the beginning of the input string, resulting in the thread pinning CPU usage at 100%. This vulnerability poses a significant risk to applications that parse arbitrary or untrusted TOML input, as a single malicious payload can effectively hang the application process. Defenders should prioritize updating the library to version 1.7.1 or later, where the parser logic has been corrected to exit the loop and return a proper `TomlError`.

## Impact

Applications that ingest and parse untrusted TOML input are highly vulnerable to service disruption. Successfully triggering this flaw causes immediate and persistent 100% CPU utilization, rendering the service unresponsive. This is particularly critical for web services or APIs that utilize `smol-toml` to process configuration files or user-provided data, potentially leading to widespread outages for dependent systems.

## Recommendation

- Upgrade `smol-toml` to version 1.7.1 or later immediately to address CVE-2026-85730.
- Audit application codebases to identify services that utilize `smol-toml` for parsing external, unvalidated TOML data.
- Implement request timeout mechanisms and resource limits (CPU/memory) on processes responsible for parsing untrusted data to mitigate the impact of potential hanging conditions.
