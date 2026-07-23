---
title: 'PostCSS: Arbitrary File Read and Information Disclosure via sourceMappingURL'
slug: 2026-07-postcss-file-read
description: A high-severity vulnerability (CVE-2026-45623) in PostCSS's `PreviousMap` component allows attackers to perform arbitrary file reads and information disclosure from the local filesystem by injecting malicious `sourceMappingURL` comments into untrusted CSS input, leading to sensitive data leakage and denial of service.
date: "2026-07-23T15:10:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - file-read
  - information-disclosure
  - supply-chain
  - nodejs
  - web-application
  - vulnerability
  - cve-2026-45623
vendors:
  - PostCSS
products:
  - postcss (<= 8.5.11)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Arbitrary file read of any file readable by the Node process from any CSS-processing context that accepts attacker-influenced CSS.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: File-existence oracle with three distinguishable response states... enabling reconnaissance of the host filesystem layout and confirmation of installed software, user accounts, and configuration files.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: DoS by targeting `/dev/zero`, `/proc/kcore`, very large files, or named pipes — `readFileSync` is a synchronous, unbounded read.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6g55-p6wh-862q
---

A critical vulnerability, tracked as CVE-2026-45623, has been identified in PostCSS, a widely used CSS processing tool. The vulnerability resides within the `PreviousMap` component, specifically affecting versions up to 8.5.11. Attackers can exploit this by embedding specially crafted `/*# sourceMappingURL=PATH */` comments into CSS input that is subsequently processed by `postcss().process()`. The `PreviousMap` component dereferences the `PATH` value against the local filesystem without proper sanitization, allowing for arbitrary file reads, including files like `/etc/passwd` or sensitive environment configuration. This can lead to the disclosure of the first approximately 10 bytes of targeted files through `JSON.parse` `SyntaxError` messages, a file-existence oracle, and potential denial of service by reading large or special device files. The flaw is triggered with PostCSS's default options, making any application that processes untrusted CSS vulnerable, including CMS themes, user-uploaded styles, and various build pipelines.

## Attack Chain

1. An attacker crafts a malicious CSS string containing a `/*# sourceMappingURL=PATH */` comment, where `PATH` specifies an arbitrary file on the target system (e.g., `/etc/passwd`).
2. The malicious CSS input is provided to a system that processes it using PostCSS's `process()` function, often within web applications, build tools, or user content rendering engines.
3. PostCSS's `Input` constructor (within `lib/input.js`) is instantiated and, during its initialization, it attempts to load a source map using the `PreviousMap` component.
4. The `PreviousMap` constructor calls `loadAnnotation` to extract the `PATH` from the CSS comment without any sanitization or validation of the provided URL.
5. Subsequently, `loadMap` is invoked. If `opts.from` is unset, the raw attacker-supplied absolute path is used. If `opts.from` is set, `path.join` is used, which does not block `..` segments, enabling path traversal to arbitrary locations like `../../../../../etc/passwd`.
6. The `loadFile` function is called with the attacker-controlled or traversed file path, which then performs a synchronous file read using `readFileSync(path, 'utf-8')`.
7. The read file content is then processed. If the content is not valid JSON (which is typical for files like `/etc/passwd`), `SourceMapConsumer` attempts to call `JSON.parse`, resulting in a `SyntaxError`.
8. The `SyntaxError` message, which includes the first ~10 bytes of the file content (e.g., "Unexpected token 'r', \"root:x:0:0\"..."), is propagated back to the application, disclosing sensitive information to the attacker.

## Impact

The vulnerability allows for an arbitrary file read of any file accessible by the Node.js process, impacting the confidentiality of sensitive data across a wide range of applications. The initial ~10 bytes leaked from the targeted file through the `JSON.parse` `SyntaxError` message are often sufficient to reveal critical information, such as SSH key headers, prefixes of API keys (`API_KEY=sk...`), `/etc/passwd` entries, or parts of process environment variables (`/proc/self/environ`). This information can be used for further exploitation. Additionally, the flaw provides a file-existence oracle, enabling attackers to map out filesystem structures and confirm the presence of specific files or configurations. A denial of service (DoS) can also be achieved by directing `readFileSync` to large files or special device files like `/dev/zero`, potentially stalling or crashing the application. Given PostCSS's extensive use in web development ecosystems, this vulnerability poses a significant risk to any system processing untrusted CSS.

## Recommendation

* **Patch `npm/postcss` immediately** to a version greater than 8.5.11 to mitigate CVE-2026-45623.
* **Audit application logging and error handling** to ensure that PostCSS error messages (specifically `SyntaxError` messages resulting from `JSON.parse`) are not exposed to untrusted users. These errors can contain fragments of sensitive file contents.
* **Implement input validation and sanitization** for all CSS input processed by PostCSS, especially in environments where user-supplied or untrusted CSS is handled. Block or strip `/*# sourceMappingURL=` comments from untrusted sources if possible.
* **Configure PostCSS with `{ map: false }`** in scenarios where previous source map handling is not required, as this explicitly disables the vulnerable functionality and is the only full short-circuit for the bug.
