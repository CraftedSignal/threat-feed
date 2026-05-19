---
title: Dasel Selector Lexer Index-Out-of-Range Panic on Trailing Backslash (CVE-2026-46377)
slug: 2026-05-dasel-panic
description: The dasel selector lexer is vulnerable to an index-out-of-range panic when tokenizing a quoted string that ends with a trailing backslash (e.g., `"\` or `'\`), leading to a process crash if an attacker can control the selector string.
date: "2026-05-19T20:11:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - panic
  - go
  - dasel
vendors:
  - Tom Wright
products:
  - dasel
affected_os:
  - Darwin
references:
  - https://github.com/advisories/GHSA-m5j3-4634-c2vq
rules:
  - title: Detect Dasel Trailing Backslash Panic (CVE-2026-46377)
    description: Detects CVE-2026-46377 exploitation — Go runtime panic in dasel due to trailing backslash in quoted string selector
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Dasel Trailing Backslash Panic (CVE-2026-46377) - macOS
    description: Detects CVE-2026-46377 exploitation — Go runtime panic in dasel due to trailing backslash in quoted string selector
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

The `dasel` library, a command-line tool and Go library for selecting and updating data structures, is vulnerable to a denial-of-service attack. Specifically, the selector lexer component within `dasel` panics when processing a quoted string that ends with a trailing backslash. This occurs due to a missing bounds check in the escape sequence handler, leading to an index-out-of-range error when the lexer attempts to read past the end of the input string. Confirmed on versions `v3.0.0` and `v3.3.1`, this vulnerability can be triggered with a minimal 2-byte input (`"\` or `'\`). An attacker who can control the selector/query string passed to dasel can trigger a Go runtime panic, crashing the process unless the caller explicitly recovers from panics.

## Attack Chain

1. An attacker crafts a malicious input string containing a quoted string that ends with a trailing backslash (e.g., `"\` or `'\`).
2. The attacker provides this malicious input string to an application that uses the `dasel` library.
3. The application passes the input string to the `lexer.NewTokenizer` function to create a new tokenizer.
4. The `Tokenize` method is called on the tokenizer to lex the input string.
5. The `parseCurRune` function is called to parse the current rune.
6. Inside `parseCurRune`, the code detects the backslash character but does not check if it's the last character in the input.
7. The `pos++` increments the position beyond the end of the input.
8. The subsequent `p.src[pos]` attempts to read past the end of the input slice, triggering a Go runtime panic and crashing the `dasel` process.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. Any application using `dasel` that processes attacker-controlled selector strings is susceptible to crashing. This can impact web applications using `dasel` for dynamic querying, applications that construct selectors from user input, and shared tooling environments where selectors are passed as parameters. The severity is high because a minimal input can cause an immediate process crash.

## Recommendation

- Upgrade to a patched version of `dasel` that includes the fix for CVE-2026-46377 once available.
- Implement input validation and sanitization on selector strings to prevent malicious inputs containing trailing backslashes in quoted strings, mitigating the risk even without a patch.
- Monitor application logs for panic errors originating from the `dasel/selector/lexer` package to detect potential exploitation attempts.
- Deploy the Sigma rule `Detect Dasel Trailing Backslash Panic (CVE-2026-46377)` to identify processes that may be crashing due to this vulnerability by detecting the "index out of range" error message.
