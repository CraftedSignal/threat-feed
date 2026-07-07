---
title: OpenClaw Vulnerability Allows Unintended Artifact Loading (CVE-2026-53813)
slug: 2026-07-openclaw-fake-package-roots
description: A high-severity vulnerability, CVE-2026-53813, in npm/openclaw versions <= 2026.4.24 allows fake package roots to influence memory-core artifact loading, potentially leading to the selection and execution of unintended local artifacts based on attacker-controlled or lower-trust input reaching the affected path.
date: "2026-07-03T12:00:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - supply-chain
  - npm
  - node.js
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw (<= 2026.4.24)
cves:
  - id: CVE-2026-53813
    cvss: 7.8
    epss: 0.00114
references:
  - https://github.com/advisories/GHSA-v8cx-933x-r976
---

A high-severity vulnerability, CVE-2026-53813, has been identified in OpenClaw (npm/openclaw package) affecting versions up to and including 2026.4.24. This flaw, dubbed "Fake package roots," permits a local package root resolution path, influenced by workspace state, to select and load memory-core artifacts from an unintended local location rather than the intended bundled artifact root. The practical impact hinges on the operator's specific configuration and the ability for lower-trust input to reach the vulnerable path. While OpenClaw generally operates on a trusted-operator model, this specific feature, if enabled and reachable, could bypass assumptions about artifact integrity. The issue was disclosed via GHSA on July 2, 2026.

## Attack Chain

The provided source describes a vulnerability rather than a detailed, observed attack chain. Exploitation would likely involve an attacker providing malicious or crafted input to a Gateway operator's workspace, leveraging the "fake package root" vulnerability (CVE-2026-53813) to redirect artifact loading. The exact steps for achieving this depend on the specific configuration and how "lower-trust input" can be introduced into the environment. No specific steps for attacker actions are outlined in the advisory.

## Impact

Successful exploitation of CVE-2026-53813 could lead to the loading of arbitrary, unintended memory-core artifacts from a local file path. The actual damage incurred is highly dependent on the operator's environment and the nature of the unintended artifact loaded. If an attacker can inject malicious code via this mechanism, it could result in code execution within the context of the affected OpenClaw process, leading to data compromise, system manipulation, or further network lateral movement.

## Recommendation

*   Patch OpenClaw (npm/openclaw) to version `2026.4.25` or newer immediately to remediate CVE-2026-53813.
*   As a mitigation for CVE-2026-53813, run memory-core flows only from trusted workspaces.
*   Keep channel and tool allowlists narrow to restrict potential attack surfaces as recommended in the advisory.
*   Avoid sharing a single OpenClaw Gateway between mutually untrusted users.
*   Disable the affected feature within OpenClaw if it is not explicitly required for operations.
