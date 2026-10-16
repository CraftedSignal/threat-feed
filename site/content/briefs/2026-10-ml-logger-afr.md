---
title: Unauthenticated Arbitrary File Read in ml-logger via CVE-2025-10952
slug: 2026-10-ml-logger-afr
description: An unauthenticated arbitrary file read vulnerability (CVE-2025-10952) in the ml-logger stream_handler allows remote attackers to enumerate and exfiltrate sensitive files from the host filesystem.
date: "2026-10-16T19:44:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:geyang:ml-logger:*:*:*:*:*:*:*:*
tags:
  - arbitrary-file-read
  - path-traversal
  - webserver
vendors:
  - Geyang
products:
  - ml-logger (<= commit acf255bade5be6ad88d90735c8367b28cbe3a743)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this by sending specially crafted paths.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attacker enumerates files on the target via the /glob endpoint.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The tool reads an arbitrary file and optionally saves it to disk.
    confidence_band: high
cves:
  - id: CVE-2025-10952
    cvss: 5.3
    epss: 0.00537
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10952
  - https://github.com/advisories/GHSA-9x36-c74v-fgr6
  - https://github.com/geyang/ml-logger/issues/74
rules:
  - title: Detect CVE-2025-10952 Exploitation Attempt
    description: Detects exploitation attempts against ml-logger using path traversal patterns in JSON keys
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1005
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect POST requests to /stream or /glob containing path traversal sequences.
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation of attack via /glob and /stream endpoints.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to ml-logger endpoints 8081 via firewall or proxy.
      owner: IT Operations
      addresses: CVE-2025-10952
      evidence: Requirement for unauthenticated network access to exploit.
---

CVE-2025-10952 is a critical vulnerability residing in the `ml-logger` Python library, specifically within the `stream_handler` component of `ml_logger/server.py`. The flaw stems from improper input validation where the `key` parameter, provided via JSON request body, is passed directly to file read operations without adequate sanitization or path restriction checks. An unauthenticated attacker can exploit this by sending specially crafted paths, such as those utilizing double leading slashes (e.g., `//root/.ssh/id_rsa`), to bypass intended directory constraints. This enables the attacker to read arbitrary files accessible by the system user running the `ml-logger` process. A functional proof-of-concept exploit is publicly available, enabling unauthenticated file enumeration via the `/glob` endpoint followed by arbitrary file exfiltration through the `/stream` endpoint.

## Attack Chain

1. Attacker identifies a target exposing the `ml-logger` API, typically on port 8081.
2. Attacker sends a POST request to the `/glob` endpoint to enumerate the filesystem and identify sensitive files.
3. Attacker parses the JSON response from the `/glob` endpoint to locate high-value targets like SSH keys, configuration files, or credentials.
4. Attacker constructs a malicious request to the `/stream` endpoint, embedding the targeted file path into the `key` JSON field.
5. Attacker prepends double slashes (e.g., `//etc/shadow`) to the file path to bypass the application's path normalization logic.
6. The `ml-logger` service retrieves the requested file from the disk and transmits the content to the attacker in the response body.
7. Attacker saves the exfiltrated content, such as a private SSH key, to their local machine.
8. Attacker uses the stolen credentials to establish persistent access or move laterally within the victim environment.

## Impact

Successful exploitation allows unauthenticated remote attackers to read sensitive files from the underlying host filesystem. This poses a severe risk of credential theft, including the acquisition of SSH private keys, environment variables, and configuration files containing secrets. If the `ml-logger` service is running with elevated privileges, the impact extends to full system compromise. The vulnerability affects all versions of `geyang/ml-logger` up to commit `acf255bade5be6ad88d90735c8367b28cbe3a743`.

## Recommendation

* Implement an authentication-enabled reverse proxy or API gateway in front of all `ml-logger` instances to restrict access to trusted sources.
* Deploy the Sigma rule below to detect path traversal attempts targeting the `ml-logger` endpoints.
* Restrict the operating system user account running `ml-logger` to the minimum necessary permissions to prevent access to sensitive files like `~/.ssh/` or `/etc/shadow`.
* Upgrade to a patched version of `ml-logger` as soon as the vendor provides a formal release addressing the vulnerability.
