---
title: HestiaCP Authenticated OS Command Injection via DNS Record Types (CVE-2025-30007)
slug: 2026-07-hestiacp-os-command-injection
description: An authenticated OS command injection vulnerability, CVE-2025-30007, in HestiaCP before version 1.9.5 allows low-privilege users to execute arbitrary commands as root by injecting a single-quote character into unvalidated DNS record types, leading to full root code execution on the underlying host.
date: "2026-07-10T19:20:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - privilege-escalation
  - linux
  - hestiacp
vendors:
  - HestiaCP
products:
  - HestiaCP < 1.9.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows low-privilege authenticated users to execute arbitrary commands as root by injecting a single-quote character into unvalidated DNS record types
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows low-privilege authenticated users to execute arbitrary commands as root
    confidence_band: high
cves:
  - id: CVE-2025-30007
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-30007
---

CVE-2025-30007 describes a critical authenticated OS command injection vulnerability affecting HestiaCP versions prior to 1.9.5. This flaw enables any low-privilege authenticated user of a HestiaCP instance to escalate their privileges to root and execute arbitrary commands on the underlying Linux operating system. The vulnerability originates from insufficient input validation within the `is_dns_record_format_valid()` function and subsequent unsafe `eval`-based parsing in `update_domain_zone()`. By injecting a specially crafted single-quote character into certain DNS record type fields during the creation or modification of a DNS record, an attacker can prematurely terminate a variable assignment string, allowing their malicious payload to be executed directly as root. This vulnerability poses a significant threat to the integrity and confidentiality of systems running affected HestiaCP installations, potentially leading to complete system compromise and data loss.

## Attack Chain

1. **Initial Access**: A low-privilege authenticated user gains access to the HestiaCP administration panel, typically through legitimate credentials or by compromising such credentials.
2. **Input Submission**: The authenticated user navigates to the DNS management section within the HestiaCP panel and attempts to create or modify a DNS record, specifically targeting a field where DNS record types are expected.
3. **Command Injection**: The user crafts a malicious payload containing a single-quote character (`'`) and injects it into the vulnerable DNS record type field, designed to break out of expected string assignments.
4. **Input Validation Bypass**: The HestiaCP function `is_dns_record_format_valid()` fails to properly sanitize or validate the malicious input, allowing the injected single-quote character and the subsequent command payload to pass through.
5. **Unsafe Parsing**: The `update_domain_zone()` function processes the unvalidated input using an `eval`-based parsing mechanism. This unsafe evaluation interprets the injected malicious payload as executable code rather than a literal string.
6. **Root Command Execution**: HestiaCP executes the attacker's arbitrary commands directly on the underlying Linux host, inheriting root privileges due to the context of the HestiaCP process.
7. **System Compromise**: With root-level command execution, the attacker achieves full control over the host system, enabling them to install backdoors, exfiltrate sensitive data, deploy malware, or further pivot within the network.

## Impact

The successful exploitation of CVE-2025-30007 grants low-privilege authenticated users complete root access to the underlying HestiaCP server. This severe impact means an attacker can take full control of the operating system, including all hosted websites, databases, and sensitive configuration files. Potential consequences include unauthorized data exfiltration, installation of persistent backdoors, deployment of ransomware, or the use of the compromised server as a platform for further attacks. This could lead to significant financial losses, reputational damage, and regulatory penalties for affected organizations.

## Recommendation

* Immediately update HestiaCP to version 1.9.5 or later to patch CVE-2025-30007.
* Review web server access logs for HestiaCP administration interfaces for unusual authentication patterns or attempts from unknown IPs.
* Monitor system process creation logs on HestiaCP servers for processes spawned by the HestiaCP user (e.g., `www-data`, `nginx`) that are not part of normal operations, especially those indicative of shell commands or reverse shells.
