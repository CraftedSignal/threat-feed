---
title: Authentication Bypass in SiYuan Publish API
slug: 2026-08-siyuan-auth-bypass
description: SiYuan versions prior to 3.7.4 contain an authentication bypass vulnerability allowing unauthenticated remote attackers to retrieve decrypted content from encrypted notebooks.
date: "2026-08-12T20:54:23Z"
lastmod: "2026-08-21T11:23:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - access-control
  - web-vulnerability
  - authentication-bypass
  - information-disclosure
  - api-security
  - remote-code-execution
  - vulnerability
  - pdf-processing
  - credential-access
  - web-application
  - xss
  - rce
  - application-security
  - ssrf
  - electron
  - path-traversal
  - cve
vendors:
  - SiYuan
products:
  - SiYuan
  - SiYuan (< 3.7.4)
  - SiYuan (<= 3.7.2)
  - SiYuan (<= 3.7.3)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Anonymous readers can enumerate and retrieve fully decrypted document content from unlocked encrypted notebooks through the publish API without authentication or key material.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: SiYuan versions before v3.7.4 fail to mask sensitive configuration fields in the /api/system/getConf endpoint, allowing anonymous or publish-reader users to obtain the session-cookie signing key.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can forge and tamper with session cookies to impersonate users, and on instances without access-auth codes configured, escalate to administrator privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: Attackers can retrieve the CookieKey value and forge valid session cookies to impersonate users or gain administrative access.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can request published blocks containing embed queries to read content from password-protected, hidden, or forbidden documents without authorization.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can call these endpoints without supplying a password to read protected document content and the complete reference topology.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can distribute malicious SiYuan documents or packages with crafted template columns that execute arbitrary SQL on a victim's kernel when the package is imported and rendered.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The application utilizes the queryBlocks function, which improperly handles raw SQL via string substitution, enabling arbitrary SQL execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw is reachable by an anonymous or RoleReader user on the publish surface.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.004
    technique_name: 'Server Software Component: SQL Injection'
    evidence: An attacker can execute arbitrary SQL, enabling cross-notebook read and write.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can inject malicious markup into annotation fields that execute as script in the PDF renderer with full Node.js access when a user opens an annotated PDF.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject markup through field descriptions or names that close containing elements and execute arbitrary code via event handlers, reaching Node built-ins due to Electron's insecure configuration.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: This allows unauthenticated remote attackers to brute-force the admin access code with unlimited automated requests and obtain full RoleAdministrator access to the kernel.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Attackers can inject event-handler attributes by including quotation marks in the color value, executing arbitrary JavaScript when viewing databases
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can access /debug/pprof/heap and related endpoints to extract in-memory secrets including AccessAuthCode and AI provider API keys.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can craft a malicious filename containing script payloads that execute with full OS command access when a user drags, drops, or pastes the file into the editor.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: allowing anonymous publish-mode readers to disclose private block content-derived text, structural metadata, and existence information for arbitrary block IDs across the workspace.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.002
    technique_name: 'Active Scanning: Vulnerability Scanning'
    evidence: This is a full-read SSRF that can be used to steal instance credentials, reach internal services, and port-scan internal infrastructure.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with admin access can write arbitrary files to any location via install operations
    confidence_band: high
cves:
  - id: CVE-2026-72789
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72789
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72793
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72794
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72795
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72801
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72804
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72807
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72809
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73041
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-fqpw-c3pj-w8g9
  - https://www.vulncheck.com/advisories/siyuan-before-remote-code-execution-via-pdf-annotations
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73042
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73043
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73046
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73050
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73052
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-g3jx-227v-x2x4
  - https://www.vulncheck.com/advisories/siyuan-before-stored-xss-via-attribute-view-field-names
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73053
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73045
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74799
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-9cqq-p2hw-mj3f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74800
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-mjf3-jwmf-r6wf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74868
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74902
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-jf56-jrhq-j2qp
  - https://www.vulncheck.com/advisories/siyuan-before-xss-to-rce-via-malicious-filename-upload
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74904
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-4vpg-gwqq-w44c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74905
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74906
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-48p5-pffc-5r9p
  - https://www.vulncheck.com/advisories/siyuan-before-incorrect-authorization-via-publish-access
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75916
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77086
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-wr4w-7vjm-mmx3
  - https://www.vulncheck.com/advisories/siyuan-before-path-traversal-via-packagename
rules:
  - title: Detect SiYuan Brute-Force Attempts via CheckAuth
    description: Detects potential brute-force activity against SiYuan /api/ endpoints by monitoring for an excessive volume of 401 Unauthorized responses
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-73045 Exploitation - Brute Force on authFilePublishAccess
    description: Detects potential brute-force activity against the SiYuan authFilePublishAccess endpoint by monitoring for high-frequency POST requests.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect Unauthenticated Access to SiYuan Debug Endpoints
    description: Detects unauthorized HTTP requests to SiYuan debug endpoints associated with CVE-2026-74799
    platform: sigma
    severity: high
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
  - title: Detect Potential CVE-2026-74800 Exploitation - Malicious Asset Upload
    description: Detects potential exploitation of CVE-2026-74800 by monitoring for HTML file uploads to the SiYuan asset management path.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
  - title: Detect Excessive 401 Unauthorized Responses to SiYuan Publish Service
    description: Detects potential brute-force activity against the SiYuan Publish Service by monitoring for high frequencies of 401 Unauthorized responses on TCP port 6808.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect Potential Exploitation of CVE-2026-74904 - SiYuan Unauthorized Block Access
    description: Detects unauthorized access attempts to SiYuan block API endpoints associated with CVE-2026-74904.
    platform: sigma
    severity: high
    tactics:
      - reconnaissance
    data_sources:
      - webserver
  - title: Detects CVE-2026-77086 Exploitation - Path Traversal in Bazaar Endpoints
    description: Detects attempts to use path traversal sequences in the packageName parameter during Bazaar install or uninstall operations.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 7
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SiYuan to version 3.7.4
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-72789 fix identified in v3.7.4
  mitigation_plan:
    - priority: immediate
      action: Disable publish API
      owner: IT Operations
      addresses: CVE-2026-72789
      evidence: Vulnerability exists within the publish API
updates:
  - at: "2026-08-18T12:52:39Z"
    level: L2
    summary: 'added detection rule: Detect Potential Exploitation of CVE-2026-74904 - SiYuan Unauthorized Block Access'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74904
  - at: "2026-08-18T12:52:48Z"
    level: L2
    summary: added coverage for SiYuan (< 3.7.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74905
  - at: "2026-08-18T12:52:55Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74906
  - at: "2026-08-19T14:33:34Z"
    level: L2
    summary: added coverage for SiYuan (<= 3.7.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75916
  - at: "2026-08-21T11:23:21Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-77086 Exploitation - Path Traversal in Bazaar Endpoints'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77086
---

SiYuan versions before 3.7.4 contain a critical authentication bypass vulnerability (CVE-2026-72789) within the application's publish API. The defect stems from an improper access control validation logic where encrypted notebooks are incorrectly treated as publicly accessible by default. When a user has unlocked an encrypted notebook, the application fails to verify the requestor's authorization, enabling anonymous remote users to enumerate and exfiltrate decrypted document content. This flaw allows attackers to bypass intended security boundaries without possessing the necessary encryption keys. Defenders should prioritize updating to v3.7.4 or later to remediate this improper authorization, which significantly exposes sensitive notebook data to unauthorized disclosure.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive, encrypted document content. Any notebook that has been unlocked by a user becomes vulnerable to retrieval by unauthenticated parties through the publish API. This impacts all SiYuan deployments currently running versions earlier than 3.7.4 that utilize the notebook publishing feature.

## Recommendation

* Update all SiYuan instances to version 3.7.4 or later immediately to patch the access control flaw.
* Audit webserver access logs for high volumes of unexpected GET requests to the publish API endpoints from unauthorized IP addresses.
* Disable the publish API feature temporarily if an immediate update to v3.7.4 is not feasible.
