---
title: Algernon handler.lua Discovery Leads to Remote Code Execution
slug: 2026-05-algernon-rce
description: Algernon is vulnerable to remote code execution due to unbounded upward directory traversal when searching for `handler.lua`, allowing attackers with write access to parent directories to execute arbitrary code.
date: "2026-05-19T14:40:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - algernon
  - rce
  - directory-traversal
vendors:
  - Algernon
products:
  - Algernon
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-xwcr-wm99-g9jc
rules:
  - title: Detect Algernon handler.lua Discovery
    description: Detects requests that could trigger the handler.lua discovery vulnerability in Algernon by looking for requests to directories without index files.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect handler.lua Creation in Parent Directories
    description: Detects the creation of handler.lua files in parent directories of common web server roots, which can be an indicator of Algernon exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Algernon is susceptible to a critical remote code execution vulnerability. When a URL path resolves to a directory lacking an index file, Algernon's `DirPage` function recursively searches parent directories for a `handler.lua` file. Critically, this search extends beyond the configured server root, creating an opportunity for attackers to inject malicious Lua code. If an attacker can write a `handler.lua` file to any parent directory of the Algernon server root, that file will be executed with full Algernon API access, including functions like `run3()`, `httpclient`, `os.execute`, and direct database access. This occurs without authentication, as the handler lookup precedes permission checks. This vulnerability impacts any Algernon deployment where a less-trusted principal can write to a parent directory of the server root. The issue was introduced due to an unbounded upward search in the `DirPage` function, as detailed in the GHSA-xwcr-wm99-g9jc advisory.

## Attack Chain

1.  Attacker identifies an Algernon instance and its server root directory.
2.  Attacker gains write access to a parent directory of the server root (e.g., `/srv`, `/tmp`, `~/`).
3.  Attacker crafts a malicious `handler.lua` file containing arbitrary code for execution.
4.  Attacker writes the malicious `handler.lua` file to the chosen parent directory.
5.  Attacker sends an HTTP request to the Algernon server, targeting a directory without an `index.*` file (e.g., `/nope/`).
6.  Algernon's `DirPage` function initiates an upward directory search for `handler.lua`.
7.  The search locates the attacker's malicious `handler.lua` in a parent directory.
8.  Algernon executes the `handler.lua` file using a Lua interpreter with full API access, resulting in RCE.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the Algernon server with the privileges of the Algernon process. This can lead to complete compromise of the server, including data theft, modification, or destruction. Multi-tenant environments are especially at risk, as a compromised tenant could inject a `handler.lua` that affects other tenants. The scope of the impact is changed, as a write primitive against a parent directory crosses into the Algernon process's authority.

## Recommendation

*   Apply the provided patch to clamp the `DirPage` directory traversal to the server root as described in the GHSA advisory.
*   Implement the boundary check in `engine/dirhandler.go` to prevent traversal beyond the server root as detailed in the fix suggestions.
*   Deploy the Sigma rule "Detect Algernon handler.lua Discovery" to identify potential exploitation attempts via web server logs.
*   Monitor file creation events in parent directories of Algernon server roots for suspicious `handler.lua` file creations using the "Detect handler.lua Creation in Parent Directories" rule.
*   Review and remove any unnecessary `handler.lua` files present in parent directories of Algernon server roots to reduce the attack surface.
