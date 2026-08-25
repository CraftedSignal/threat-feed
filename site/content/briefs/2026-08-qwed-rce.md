---
title: Authenticated Remote Code Execution in qwed via Unsafe SymPy Parsing
slug: 2026-08-qwed-rce
description: The qwed package (version 5.1.1) fails to sanitize input in math verification endpoints, allowing authenticated attackers to achieve remote code execution via unsafe SymPy expression evaluation.
date: "2026-08-25T18:50:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - input-validation
  - python
products:
  - qwed (5.1.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because parse_expr() internally calls Python's eval(), any authenticated tenant can execute arbitrary Python code inside the API server process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q27q-98j4-9pfv
rules:
  - title: Detect qwed Authenticated RCE Attempt via Malicious Math Expression
    description: Detects exploitation attempts against qwed where the math expression field contains suspicious Python-like syntax or module imports.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Monitor logs for POST requests to /verify/math and /verify/batch containing import or subprocess strings
      owner: SOC
      due: 24h
      evidence: Source provides explicit attack vector via SymPy parse_expr() eval
  mitigation_plan:
    - priority: immediate
      action: Upgrade qwed to a version containing fixed input sanitization
      owner: IT Operations
      addresses: qwed 5.1.1
      evidence: Source advisory indicates fix required via input sanitization
---

The qwed package, specifically version 5.1.1, contains an authenticated remote code execution (RCE) vulnerability stemming from the unsafe use of `sympy.parsing.sympy_parser.parse_expr()`. The application exposes two primary endpoints, `POST /verify/math` and `POST /verify/batch`, which accept user-supplied mathematical expressions. These inputs are passed directly to `parse_expr()` without configuring a restricted namespace for the underlying `eval()` call. Any user, including those creating new accounts via the default-enabled `/auth/signup` endpoint, can supply arbitrary Python code within these expressions. This allows for full server-side command execution under the context of the running application process. The lack of sandbox parameters (`global_dict` and `local_dict`) in the SymPy calls effectively disables Python's built-in security boundaries, enabling attackers to read files, modify the local database, or execute OS-level commands.

## Attack Chain

1. Attacker interacts with the `POST /auth/signup` endpoint to create a standard, unprivileged tenant account.
2. Attacker uses the returned JWT to authenticate requests to the `POST /auth/api-keys` endpoint to generate a persistent API key.
3. Attacker identifies the `POST /verify/math` or `POST /verify/batch` endpoints as injection sinks for user-supplied math queries.
4. Attacker constructs a malicious Python expression payload using `pathlib` or `os` modules to interact with the host filesystem.
5. Attacker submits the payload within the JSON `expression` field (for `/verify/math`) or `query` field (for `/verify/batch`) using the previously generated API key.
6. The server application receives the request and passes the unvalidated input string directly to the vulnerable `parse_expr()` function.
7. The SymPy library evaluates the injected Python code string via `eval()` within the process memory space.
8. Final objective reached: arbitrary command execution, leading to complete server compromise or data exfiltration.

## Impact

Successful exploitation results in full remote code execution, granting the attacker the same permissions as the system user running the qwed API server. This permits unauthorized read/write access to the host filesystem, exfiltration of environment variables containing sensitive secrets (e.g., `QWED_JWT_SECRET_KEY`), modification of persistent data, and potential lateral movement within the container or host environment.

## Recommendation

Prioritize patching the qwed package to a version that sanitizes all input passed to SymPy's `parse_expr()` function. If upgrading is not immediately possible, implement strict input validation to ensure math expressions only contain alphanumeric characters and expected mathematical operators, preventing the injection of Python syntax. Additionally, utilize the provided Sigma detection rule to monitor for suspicious POST requests to verification endpoints containing Python built-ins or module import syntax.
