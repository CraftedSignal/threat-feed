---
title: Arbitrary Code Execution via JavaScript Frontmatter in Prompty TypeScript Loader
slug: 2026-07-arbitrary-code-execution-prompty
description: A high-severity vulnerability, CVE-2026-53597, in the Prompty TypeScript loader (`@prompty/core`) versions `>= 2.0.0-alpha.1 < 2.0.0-beta.3` allows arbitrary JavaScript code execution in the host Node.js process when parsing untrusted `.prompty` files due to improper handling of `gray-matter`'s executable frontmatter engines.
date: "2026-07-17T19:54:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-code-execution
  - supply-chain
  - vulnerability
  - nodejs
  - typescript
vendors:
  - Prompty
products:
  - '@prompty/core'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker-controlled `.prompty` file could therefore execute arbitrary JavaScript during prompt loading.
    confidence_band: high
cves:
  - id: CVE-2026-53597
    epss: 0.0093
references:
  - https://github.com/advisories/GHSA-c4gh-rv8h-q9vw
  - CVE-2026-53597
---

A critical vulnerability, tracked as CVE-2026-53597, affects the Prompty TypeScript loader, specifically the `@prompty/core` npm package in versions `>= 2.0.0-alpha.1` up to but not including `2.0.0-beta.3`. The vulnerability stems from the library's use of `gray-matter` for parsing frontmatter in `.prompty` files without properly disabling or overriding executable frontmatter engines. `gray-matter`, by default, supports and evaluates JavaScript frontmatter blocks, indicated by `---js`. This oversight allows an attacker to craft a malicious `.prompty` file containing arbitrary JavaScript code within such a block. When an application loads and parses this untrusted file, the embedded JavaScript is executed in the context of the host Node.js process, leading to arbitrary code execution. This poses a significant risk to applications that process user-provided or untrusted `.prompty` files, prompt paths, or prompt bundles.

## Attack Chain

1. An attacker crafts a malicious `.prompty` file containing a `---js` frontmatter block.
2. Within this JavaScript frontmatter block, the attacker embeds arbitrary JavaScript code designed to achieve their objective (e.g., remote code execution, data exfiltration).
3. The attacker delivers this malicious `.prompty` file to a victim organization, potentially through social engineering or by placing it in an accessible repository.
4. A victim application, utilizing the vulnerable `@prompty/core` package (versions `>= 2.0.0-alpha.1 < 2.0.0-beta.3`), loads or processes the untrusted `.prompty` file.
5. During the parsing process, `@prompty/core` invokes the `gray-matter` library to extract and process the file's frontmatter.
6. As `@prompty/core` does not override `gray-matter`'s default behavior, the `---js` frontmatter engine is activated and the embedded JavaScript code is evaluated.
7. The attacker's arbitrary JavaScript payload executes with the permissions of the Node.js process running the victim application.
8. This leads to arbitrary code execution on the host system, potentially enabling system compromise, data theft, or further lateral movement within the network.

## Impact

Applications that load untrusted `.prompty` files or prompt bundles from less-trusted locations are susceptible to arbitrary JavaScript execution. If exploited, an attacker could execute arbitrary code within the host Node.js process, potentially leading to full system compromise, data exfiltration, or disruption of service. This can result in significant financial, reputational, and operational damage, depending on the privileges and sensitive data accessible by the compromised Node.js application. While specific victim counts are not available, any organization deploying applications using the vulnerable `@prompty/core` versions that handle untrusted inputs is at risk.

## Recommendation

* Upgrade the `@prompty/core` package to version `2.0.0-beta.3` or later immediately to remediate the CVE-2026-53597 vulnerability.
* Ensure that application environments are configured to prevent the execution of untrusted code, even if a parsing vulnerability exists.
