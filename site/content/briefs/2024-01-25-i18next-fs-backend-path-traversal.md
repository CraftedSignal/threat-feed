---
title: i18next-fs-backend Path Traversal Vulnerability
slug: 2024-01-25-i18next-fs-backend-path-traversal
description: i18next-fs-backend versions before 2.6.4 are vulnerable to path traversal due to insufficient sanitization of the lng and ns values, potentially allowing attackers to read arbitrary files, overwrite files, or execute code if .js or .ts locale files are in use.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - i18next
  - arbitrary-file-read
  - arbitrary-file-write
  - code-execution
vendors:
  - npm
products:
  - i18next-fs-backend
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-8847-338w-5hcj
rules:
  - title: Detect i18next-fs-backend Path Traversal Attempt via HTTP Request
    description: Detects attempts to exploit the i18next-fs-backend path traversal vulnerability by identifying suspicious directory traversal sequences in the lng or ns parameters of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect i18next-fs-backend .js/.ts Eval Code Execution Attempt
    description: Detects attempts to exploit the i18next-fs-backend .js/.ts eval vulnerability via malicious filenames.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The i18next-fs-backend library, a file system backend for the i18next internationalization framework, is vulnerable to a path traversal attack in versions prior to 2.6.4. This vulnerability arises from the unsanitized use of the `lng` (language) and `ns` (namespace) parameters when constructing file paths for loading and writing locale files. If an application exposes the language code to user input, an attacker can craft a malicious `lng` or `ns` value containing directory traversal sequences (e.g., `../`) to escape the intended locale directory. Successful exploitation can lead to arbitrary file read, arbitrary file overwrite, and, if `.js` or `.ts` files are used for localization, arbitrary code execution. This vulnerability highlights the importance of input validation, especially when constructing file paths from user-controlled data. The vulnerability was patched in version 2.6.4.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of `i18next-fs-backend` (versions prior to 2.6.4) and exposes the language code to user input via query parameters (e.g., `?lng=`), cookies, or request headers.
2. The attacker crafts a malicious `lng` value containing directory traversal sequences, such as `../../../../etc`, to target sensitive files outside the intended locale directory.
3. The attacker sends a request to the application with the crafted `lng` parameter.
4. The application passes the unsanitized `lng` value to the `i18next.t()` function.
5. The `i18next-fs-backend` library interpolates the malicious `lng` value into the `loadPath` configuration option, without proper validation.  For example, `loadPath: '/locales/{{lng}}/{{ns}}.json'` becomes `/locales/../../../../etc/{{ns}}.json`.
6. The backend attempts to read the file specified by the crafted path (e.g., `/etc/passwd`).
7. If successful, the contents of the targeted file are returned as a translation resource, potentially exposing sensitive information. If the attacker crafted the `lng` or `ns` value to point to a `.js` or `.ts` file containing malicious code, the backend will execute the file using `eval()`, leading to arbitrary code execution on the server.
8. Alternatively, if the application attempts to write a missing translation key using the crafted path (via `addPath`), the attacker could overwrite arbitrary files on the system, potentially leading to application compromise.

## Impact

Successful exploitation of this vulnerability can have severe consequences. Arbitrary file read allows attackers to access sensitive data, such as configuration files, database credentials, or application source code. Arbitrary file overwrite can lead to application malfunction or complete compromise. If the application uses `.js` or `.ts` files for localization and the attacker is able to inject malicious code into those files through path traversal, arbitrary code execution can result, potentially allowing the attacker to gain full control of the server. The number of victims depends on the popularity and configuration of applications using the vulnerable `i18next-fs-backend` library.

## Recommendation

*   Upgrade to `i18next-fs-backend` version 2.6.4 or later to patch the path traversal vulnerability as this version introduces the `isSafePathSegment` and `interpolatePath` functions to sanitize the path.
*   If upgrading is not immediately feasible, sanitize the `lng` and `ns` values at the application boundary before passing them to `i18next`. Reject values containing `..`, `/`, `\`, control characters, and limit the length to prevent path traversal as mentioned in the advisory.
*   If using `.js` or `.ts` locale files, carefully review them for any suspicious or unexpected code. The advisory highlights that these files must be treated as trusted code.
*   Monitor web server logs for suspicious requests containing directory traversal sequences in the `lng` or `ns` parameters. Deploy the first Sigma rule for this purpose.
