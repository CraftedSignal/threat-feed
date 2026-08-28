---
title: Remote Code Execution via Malicious Plugin Upload in Budibase
slug: 2026-08-budibase-rce
description: Authenticated administrators can exploit an insecure plugin handling mechanism in Budibase versions prior to 3.41.3 to achieve remote code execution via malicious JavaScript tarball uploads.
date: "2026-08-28T13:13:17Z"
lastmod: "2026-08-28T13:14:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - budibase
vendors:
  - Budibase
products:
  - Budibase (< 3.41.3)
  - Budibase
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The server calls eval() on plugin JavaScript files without sandboxing in the main Node.js process.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: enabling attackers to exfiltrate environment variables and credentials with root privileges in default deployments.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with BASIC role can submit crafted query requests with target table identifiers to bypass table-level access controls and manipulate restricted data.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated app-scoped builder to grant builder access to unrelated apps.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Budibase versions prior to 3.41.3 are vulnerable to a missing authorization flaw in the POST /api/resources/duplicate endpoint.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attackers can inject resources by specifying an arbitrary destination workspace ID in the request body, then trigger injected automations with outgoing webhooks to exfiltrate data from victim applications.
    confidence_band: high
cves:
  - id: CVE-2026-82244
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82244
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82239
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82240
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82242
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82245
rules:
  - title: Detect Exploitation of CVE-2026-82242 - Authorization Bypass in Budibase
    description: Detects potential exploitation attempts of CVE-2026-82242 by monitoring POST requests to the /api/resources/duplicate endpoint which may indicate unauthorized resource injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Budibase to 3.41.3 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor patch recommendation for CVE-2026-82244
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access
      owner: Security Operations
      addresses: CVE-2026-82244
      evidence: Vulnerability requires authenticated admin privileges
updates:
  - at: "2026-08-28T13:13:33Z"
    level: L2
    summary: added coverage for Budibase (< 3.41.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82239
  - at: "2026-08-28T13:13:55Z"
    level: L2
    summary: added coverage for Budibase
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82240
  - at: "2026-08-28T13:14:12Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-82242 - Authorization Bypass in Budibase'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82242
  - at: "2026-08-28T13:14:22Z"
    level: L2
    summary: added coverage for Budibase
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82245
---

Budibase versions prior to 3.41.3 contain a critical remote code execution (RCE) vulnerability related to how the application handles plugin uploads. An authenticated user with administrator privileges can upload a specifically crafted plugin tarball containing malicious JavaScript code. The application's backend improperly handles these plugin files by invoking the JavaScript contents through the eval() function within the primary Node.js process. Because this process lacks sandboxing, the arbitrary code runs with the full privileges of the Budibase service. This vulnerability poses a severe risk to internal infrastructure, as attackers can leverage the execution context to exfiltrate sensitive environment variables, access database credentials, and potentially gain further persistence within the server environment.

## Impact

Successful exploitation allows an authenticated administrator to achieve full remote code execution on the underlying server. This enables the complete compromise of the Budibase installation, potential access to linked data sources, and the exfiltration of sensitive configuration secrets, such as API keys and database credentials stored in environment variables.

## Recommendation

- Upgrade all Budibase instances to version 3.41.3 or later immediately to patch the insecure plugin handling mechanism.
- Audit logs for administrative user activity, specifically monitoring for plugin upload events or modifications to the plugin directory.
- Review access control policies for the Budibase platform to ensure that the administrative role is restricted to trusted personnel only.
- Implement network segmentation for the Budibase server to limit the potential blast radius if the application process is compromised.
