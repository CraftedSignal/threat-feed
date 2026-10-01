---
title: Tornado StaticFileHandler Symlink Path Traversal
slug: 2026-10-tornado-path-traversal
description: A path traversal vulnerability in Tornado's StaticFileHandler allows unauthenticated remote attackers to read arbitrary files via symbolic links within the static root directory.
date: "2026-10-01T04:20:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - python
  - tornado
vendors:
  - Tornado
products:
  - Tornado (<= 6.5.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can read any file readable by the process user.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The handler uses os.path.abspath() for directory traversal checks, which normalizes paths but does not resolve symbolic links.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c2m8-h5v5-343r
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit static directories for symlinks and restrict serving them via web server configuration.
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies symlink behavior as the root cause.
  hunt_leads:
    - lead: Request patterns for sensitive file extensions in static root paths.
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker retrieves sensitive files such as /etc/passwd or configuration files.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tornado to the patched version.
      owner: IT Operations
      addresses: Tornado (<= 6.5.8)
      evidence: Source identifies 6.5.8 as vulnerable.
---

Tornado versions 6.5.8 and earlier contain a path traversal vulnerability in the `StaticFileHandler` component that permits unauthenticated attackers to read arbitrary files from the filesystem. The vulnerability exists because `get_absolute_path` and `validate_absolute_path` utilize `os.path.abspath()` to normalize requested paths and validate them against the configured static root. While `os.path.abspath()` correctly normalizes directory traversal sequences like `..`, it fails to resolve symbolic links. Subsequent file access operations (such as `os.path.isfile()`) resolve these symlinks to their actual targets.

If an application serves a static directory containing symlinks - often introduced by build pipelines, web frameworks, or improper user-uploaded file handling - an attacker can traverse outside the intended static root by requesting a path that resolves through a symlink to sensitive files like configuration credentials, private keys, or system files. Defending organizations must ensure that `StaticFileHandler` is not used to serve directories containing untrusted or externally-linked content, or upgrade to a version incorporating `os.path.realpath()` for validation.

## Attack Chain

1. Attacker identifies a target application utilizing the `tornado.web.StaticFileHandler`.
2. Attacker confirms the existence of a symbolic link within the application's static directory pointing to a sensitive file (e.g., `/etc/passwd` or `/app/config.json`).
3. Attacker sends a GET request to the Tornado server targeting the identified symlink (e.g., `GET /static/symlink_name HTTP/1.1`).
4. The `StaticFileHandler` invokes `validate_absolute_path`, which uses `os.path.abspath()` to check if the path starts with the configured static root.
5. `os.path.abspath()` considers the path valid because it resides within the static directory structure as a string, ignoring that it is a symlink.
6. The application proceeds to the file access stage where `os.path.isfile()` and subsequent read operations resolve the symlink target.
7. The server reads the file content from the target location and returns the sensitive data to the attacker in the HTTP response body.

## Impact

Successful exploitation allows unauthenticated remote attackers to read any file readable by the user account running the Tornado application process. Depending on the environment, this typically includes application configuration secrets, database connection strings, TLS private keys, SSH keys, source code, and sensitive system files like `/etc/shadow`. This vulnerability impacts any deployment where the static root contains symlinks, which is a common scenario in modern development environments using Docker volume mounts, webpack-based build tools, or `npm link`.

## Recommendation

* Upgrade Tornado to a version that implements `os.path.realpath()` for directory validation to resolve and restrict symlinks to the static root.
* Identify and audit all directories served by `StaticFileHandler` for the presence of symbolic links using `find /path/to/static -type l`.
* Implement file system permissions that restrict the Tornado process user from accessing sensitive files outside of its intended scope as a defense-in-depth measure.
* Monitor web server logs for suspicious requests to files typically not served as static assets, such as files ending in `.conf`, `.key`, `.pem`, or system configuration files.
