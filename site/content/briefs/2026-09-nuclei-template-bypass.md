---
title: Nuclei Template Signature Verification Bypass
slug: 2026-09-nuclei-template-bypass
description: Nuclei versions before 3.11.1 are vulnerable to template signature bypass due to reliance on file modification timestamps for cache validation, allowing attackers to inject malicious templates.
date: "2026-09-16T19:52:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:projectdiscovery:nuclei:*:*:*:*:*:*:*:*
vendors:
  - ProjectDiscovery
products:
  - Nuclei (< 3.11.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can replace a legitimate, verified template with a malicious one and restore the original modification timestamp, causing the scanner to execute the malicious template and potentially leading to arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-92718
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92718
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Nuclei to version 3.11.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrade to 3.11.1 for fix
  mitigation_plan:
    - priority: immediate
      action: Restrict file system permissions on template directories to prevent unauthorized modifications
      owner: Security Engineering
      addresses: CVE-2026-92718
      evidence: Source describes template replacement as the primary attack vector
---

Nuclei versions prior to 3.11.1 contain a critical flaw in the template signature verification process. The application attempts to optimize performance by caching the results of signature verification based solely on the file modification timestamp (mtime) of the template rather than utilizing cryptographic checksums. An attacker who has gained local access to the system can replace a legitimate, previously verified template with an unsigned, malicious variant. By restoring the original modification timestamp of the file, the attacker forces the Nuclei engine to treat the malicious content as validly signed. When Nuclei executes the tampered template, it may perform unauthorized actions, including the execution of arbitrary operating system commands, depending on the capabilities defined in the malicious template. This vulnerability is particularly impactful in automated pipeline environments where Nuclei is trusted to perform security scans.

## Attack Chain

1. Attacker gains unauthorized file system access to the directory containing Nuclei templates.
2. Attacker identifies a legitimate template that has already been verified and cached by Nuclei.
3. Attacker modifies the template file to include malicious instructions or payloads capable of OS command execution.
4. Attacker updates the file modification timestamp of the malicious template to match the original timestamp of the legitimate file.
5. Attacker triggers a scan or waits for the next scheduled execution of the Nuclei scanner.
6. Nuclei performs a cache lookup, confirms the modification time matches the cached state, and skips re-verification.
7. The Nuclei engine executes the tampered template as a trusted entity.
8. Final objective is achieved: arbitrary code execution on the host running the Nuclei scanner.

## Impact

Successful exploitation allows for arbitrary command execution under the privileges of the Nuclei process. This represents a significant risk for organizations relying on Nuclei in CI/CD pipelines, automated security orchestration, or local security tooling. If exploited, an attacker could escalate local access to full system control or pivot further into the internal network from the scanning host.

## Recommendation

1. Upgrade all instances of Nuclei to version 3.11.1 or later to implement secure cryptographic template verification.
2. Implement file integrity monitoring (FIM) on directories storing Nuclei templates to alert on unexpected file modifications.
3. Restrict file system permissions for the directory containing Nuclei templates, ensuring only the service account running the scanner has write access.
4. Conduct an audit of existing templates to identify unauthorized modifications.
