---
title: Vanna FileSystemConversationStore Path Traversal Vulnerability (CVE-2026-65702)
slug: 2026-07-vanna-path-traversal
description: Vanna versions up to and including 2.0.2 contain a path traversal vulnerability in its FileSystemConversationStore persistence integration, allowing unauthenticated remote attackers to write attacker-controlled JSON files to arbitrary server filesystem locations and read conversation metadata or other files from outside the intended base directory by supplying path traversal sequences within the 'conversation_id' parameter to unauthenticated chat API endpoints.
date: "2026-07-23T18:29:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-write
  - file-read
  - vulnerability
  - web-application
  - cve
vendors:
  - Vanna
products:
  - Vanna <= 2.0.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Vanna through 2.0.2 contains a path traversal vulnerability in the FileSystemConversationStore persistence integration that allows unauthenticated remote attackers to write attacker-controlled JSON files to arbitrary filesystem locations and read conversation metadata from outside the intended store base directory.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can supply path traversal sequences in the conversation_id parameter ... enabling ... unauthorized file read on the server filesystem.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Stored Data Manipulation
    evidence: Attackers can supply path traversal sequences in the conversation_id parameter ... enabling arbitrary file write with attacker-controlled content
    confidence_band: high
cves:
  - id: CVE-2026-65702
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65702
rules:
  - title: Detects CVE-2026-65702 Exploitation - Vanna FileSystemConversationStore Path Traversal
    description: Detects exploitation attempts for CVE-2026-65702, a path traversal vulnerability in Vanna's FileSystemConversationStore. This rule identifies path traversal sequences (e.g., '../', '..\') within the 'conversation_id' parameter in web server access logs targeting unauthenticated chat API endpoints.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - impact
      - initial_access
    techniques:
      - T1083
      - T1190
      - T1565
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-65702, has been identified in Vanna through version 2.0.2. This flaw resides within the `FileSystemConversationStore` persistence integration, which is responsible for storing conversation metadata. Unauthenticated remote attackers can exploit this vulnerability by manipulating the `conversation_id` parameter within requests sent to Vanna's unauthenticated chat API endpoints. By injecting path traversal sequences (e.g., `../`, `..\`), attackers can escape the intended base directory. This allows them to perform arbitrary file write operations, injecting attacker-controlled JSON content into any location on the server's filesystem. Furthermore, the same mechanism enables unauthorized file read operations, allowing attackers to access conversation metadata or other sensitive files located outside the designated storage directory, potentially leading to data exfiltration or further system compromise.

## Attack Chain

1. An unauthenticated remote attacker identifies a Vanna instance running version 2.0.2 or earlier, exposed to the internet.
2. The attacker crafts a malicious HTTP request, targeting Vanna's unauthenticated chat API endpoints.
3. In the crafted request, the attacker includes path traversal sequences (e.g., `../`, `..\`, or their URL-encoded equivalents) within the `conversation_id` parameter in the URL query string.
4. For arbitrary file *write* operations, the attacker includes attacker-controlled JSON content within the request body (typically a POST request). The manipulated `conversation_id` dictates the arbitrary filesystem path where this JSON content will be written.
5. For arbitrary file *read* operations, the attacker submits a request where the `conversation_id` parameter is set to a path traversal sequence leading to a target file (e.g., `conversation_id=../../../../etc/passwd`).
6. Vanna's `FileSystemConversationStore` component processes the request and incorrectly resolves the manipulated `conversation_id` parameter, failing to properly sanitize the input.
7. This misinterpretation results in the server either writing the attacker-controlled JSON file to an arbitrary location on the filesystem or reading the content of the specified arbitrary file from the server's filesystem.
8. The attacker successfully writes malicious content (e.g., a web shell) or exfiltrates sensitive data read from the system, potentially leading to remote code execution or complete system compromise.

## Impact

The successful exploitation of CVE-2026-65702 allows unauthenticated attackers to achieve arbitrary file write and read capabilities on the vulnerable Vanna server. This directly translates to significant risks, including unauthorized data exposure, system tampering, and potential remote code execution (RCE) if the attacker can write a web shell or overwrite critical system files. Organizations using vulnerable Vanna versions are at risk of complete system compromise, data breaches, and service disruption. The impact is critical due to the unauthenticated nature of the vulnerability and the broad capabilities it grants to an attacker, affecting the integrity, confidentiality, and availability of the affected system.

## Recommendation

* Patch CVE-2026-65702 immediately by upgrading Vanna to a version greater than 2.0.2.
* Deploy the provided Sigma rule to your SIEM to detect exploitation attempts against Vanna's chat API endpoints, specifically looking for `conversation_id` parameters containing path traversal sequences in web server logs.
* Monitor web server access logs (category `webserver`) for HTTP requests containing suspicious path traversal indicators, especially within query parameters.
