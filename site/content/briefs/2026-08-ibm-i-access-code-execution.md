---
title: Arbitrary Code Execution in IBM i Access Client Solutions
slug: 2026-08-ibm-i-access-code-execution
description: IBM i Access Client Solutions versions 1.1.2.0 through 1.1.9.13 contain a local arbitrary code execution vulnerability on Windows due to insecure file permissions on a configuration file.
date: "2026-08-12T22:52:22Z"
lastmod: "2026-08-12T22:52:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - local-privilege-escalation
  - windows
vendors:
  - IBM
products:
  - i Access Client Solutions
  - i Access Client Solutions (1.1.2.0-1.1.9.13)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM i Access Client Solutions 1.1.2.0 through 1.1.9.13 is vulnerable to arbitrary code execution on Windows when installed for all users due to publicly writeable configuration file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: IBM i Access Client Solutions 1.1.2.0 through 1.1.9.13 is vulnerable to zip slip path traversal exploit when importing a configuration.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: IBM i Access Client Solutions 1.1.2.0 through 1.1.9.13 could allow a local attacker to execute arbitrary code due to improper neutralization of special elements used in an OS command.
    confidence_band: high
cves:
  - id: CVE-2026-13094
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13094
  - https://www.ibm.com/support/pages/node/7282954
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13105
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16695
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM i Access Client Solutions to version 1.1.9.14 or later
      owner: IT Operations
      due: 72h
      evidence: Vendor recommendation for CVE-2026-13094
  mitigation_plan:
    - priority: immediate
      action: Review and harden file permissions for application configuration files
      owner: IT Operations
      addresses: CVE-2026-13094
      evidence: NVD vulnerability description
updates:
  - at: "2026-08-12T22:52:31Z"
    level: L2
    summary: added coverage for i Access Client Solutions (1.1.2.0-1.1.9.13)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-13105
  - at: "2026-08-12T22:52:58Z"
    level: L2
    summary: added coverage for i Access Client Solutions
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16695
---

IBM i Access Client Solutions (ACS) versions 1.1.2.0 through 1.1.9.13 are vulnerable to arbitrary code execution on Windows systems when installed for all users. The vulnerability stems from insecure write permissions applied to a configuration file during installation. A local attacker with authenticated access can modify this file to inject malicious code or arguments, which are subsequently executed with the privileges of the user running the application. This vulnerability is assigned CVE-2026-13094 and carries a CVSS score of 7.8 (High). Impacted organizations should apply the updates provided by IBM to remediate the insecure configuration file permissions.

## Attack Chain

1. Attacker establishes local access to a Windows system where IBM i Access Client Solutions is installed for all users.
2. Attacker enumerates the ACS installation directory and subdirectories to locate configuration files.
3. Attacker identifies a configuration file with weak discretionary access control lists (DACLs) permitting non-administrative write access.
4. Attacker modifies the configuration file to include malicious commands or point to a malicious library/script.
5. An authorized user (or elevated service) launches the IBM i Access Client Solutions application.
6. The application parses the malicious configuration file during initialization.
7. The application executes the injected code or triggers the malicious path during runtime.
8. Final objective is achieved: execution of arbitrary code in the context of the user running the application.

## Impact

Successful exploitation allows a local attacker to execute arbitrary code on the affected Windows system. This can lead to local privilege escalation, persistence, or data theft, depending on the privileges of the user executing the application. The vulnerability affects all deployments of IBM i Access Client Solutions 1.1.2.0 through 1.1.9.13 installed in a multi-user context.

## Recommendation

Prioritized actions for security teams:
- Update IBM i Access Client Solutions to a patched version as advised by the vendor in the official support bulletin (CVE-2026-13094).
- Use File Integrity Monitoring (FIM) or audit logs to detect unauthorized modifications to application configuration files in 'C:\\ProgramData' or 'C:\\Program Files'.
- Review the permissions of the configuration files for IBM software to ensure they are restricted to Administrators and SYSTEM accounts.
