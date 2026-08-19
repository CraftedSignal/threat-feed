---
title: Arbitrary Command Execution in Splunk MCP Server App via Insecure Deserialization
slug: 2026-08-splunk-mcp-deserialization
description: Splunk MCP Server app versions below 1.2.1 are vulnerable to remote code execution due to improper deserialization of untrusted data in the credential management component, allowing users with administrative privileges to execute arbitrary commands.
date: "2026-08-19T22:39:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Splunk
products:
  - Splunk MCP Server app
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A user who holds the admin Splunk role could execute arbitrary commands on the underlying operating system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability is possible because of missing input validation in the app's credential management component, which deserializes stored data without checking whether the content is of the expected type.
    confidence_band: high
cves:
  - id: CVE-2026-76404
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76404
  - https://advisory.splunk.com/advisories/SVD-2026-0808
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Splunk MCP Server app to version 1.2.1 or higher.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76404 requires update to 1.2.1 to resolve.
  mitigation_plan:
    - priority: immediate
      action: Restrict Splunk administrative roles to authorized personnel only.
      owner: IT Operations
      addresses: CVE-2026-76404
      evidence: Exploitation requires administrative role.
---

Splunk MCP Server app versions prior to 1.2.1 contain a critical security vulnerability, tracked as CVE-2026-76404, stemming from insecure deserialization of untrusted data. The vulnerability resides in the application's credential management component, which fails to perform adequate input validation before deserializing stored data. An attacker who has successfully compromised or holds an account with 'admin' level privileges within the Splunk environment can exploit this flaw to execute arbitrary commands on the underlying host operating system. This issue represents a significant risk for organizations where administrative access is shared or delegated, as the vulnerability effectively allows for privilege escalation from a legitimate Splunk administrative role to full host-level control.

## Impact

Successful exploitation allows an authenticated administrative user to achieve full command execution on the host running the Splunk MCP Server. This could lead to complete system compromise, unauthorized access to sensitive data, and potential lateral movement within the enterprise network. Organizations utilizing Splunk MCP Server versions below 1.2.1 should prioritize upgrading to the patched version immediately to mitigate this risk.

## Recommendation

* Upgrade the Splunk MCP Server app to version 1.2.1 or higher immediately to address CVE-2026-76404.
* Audit logs for suspicious command execution originating from the Splunk MCP Server service account or associated service processes.
* Review administrative user access to the Splunk environment to ensure compliance with the principle of least privilege, minimizing the number of users who hold the 'admin' role required to trigger this vulnerability.
