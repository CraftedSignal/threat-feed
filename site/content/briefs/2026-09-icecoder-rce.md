---
title: Remote Code Execution in ICEcoder via Command Injection
slug: 2026-09-icecoder-rce
description: Authenticated users can execute arbitrary commands on ICEcoder installations through version 8.1 by exploiting a command injection flaw in lib/properties.php.
date: "2026-09-10T15:09:25Z"
type: advisory
types:
  - advisory
severities:
  - high
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can create directories with shell metacharacters in their names and access the Properties function to execute arbitrary commands as the web-server user via popen().
    confidence_band: high
cves:
  - id: CVE-2026-64837
    cvss: 8.8
rules:
  - title: Detects CVE-2026-64837 Exploitation - Command Injection in lib/properties.php
    description: Detects exploitation of CVE-2026-64837 by identifying shell metacharacters in requests directed to the ICEcoder Properties function
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade ICEcoder to a version beyond 8.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-64837 documentation
  hunt_leads:
    - lead: Search web logs for requests to /lib/properties.php containing common shell metacharacters
      technique_id: T1059.004
      data_needed:
        - web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-64837 description
  mitigation_plan:
    - priority: immediate
      action: Restrict web-server user permissions to prevent execution of arbitrary binaries
      owner: IT Operations
      addresses: CVE-2026-64837
      evidence: NVD vulnerability details
---

ICEcoder versions through 8.1 contain a command injection vulnerability in `lib/properties.php`. The vulnerability arises because the application fails to properly escape filesystem paths before passing them to a shell command using the `popen()` function. An authenticated attacker can exploit this by creating a directory with a name containing shell metacharacters and subsequently invoking the Properties function within the ICEcoder interface. This results in the execution of arbitrary commands with the permissions of the underlying web server process. Because the application processes user-controlled directory paths directly, the vulnerability allows for reliable remote code execution once the attacker successfully creates the malicious directory structure.

## Attack Chain

1. Attacker authenticates to the target ICEcoder instance.
2. Attacker uses the built-in file management capabilities to create a new directory on the server.
3. Attacker names the directory using shell metacharacters (e.g., `;`, `|`, `&&`, or backticks).
4. Attacker navigates to the Properties function within the ICEcoder web interface for the newly created directory.
5. The application backend in `lib/properties.php` retrieves the malicious directory path.
6. The application passes the unescaped path string to the system shell via `popen()`.
7. The operating system interprets the metacharacters, executing the attacker-supplied payload.
8. Arbitrary code is executed under the context of the web server service user (e.g., `www-data` or `apache`).

## Impact

Successful exploitation grants an attacker arbitrary command execution on the host server. This can lead to full system compromise, data exfiltration, lateral movement within the network, or deployment of additional malicious tools. This vulnerability is particularly critical for web environments where the web server user may have significant filesystem permissions.

## Recommendation

Prioritize the immediate update of ICEcoder to a version beyond 8.1 that contains the necessary input sanitization for `lib/properties.php`. If an update is not immediately feasible, restrict access to the ICEcoder interface to trusted users via network-level controls such as a VPN or an IP allowlist. Detection teams should monitor web server logs for suspicious POST requests to the `lib/properties.php` endpoint that contain shell metacharacters.

## Affected Assets

- affected_vendors:
 - "ICEcoder"
- affected_products:
 - "ICEcoder (<= 8.1)"

## References

- https://nvd.nist.gov/vuln/detail/CVE-2026-64837
