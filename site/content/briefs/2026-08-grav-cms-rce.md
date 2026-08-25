---
title: Remote Code Execution in Grav CMS Flex Objects Plugin
slug: 2026-08-grav-cms-rce
description: Authenticated users can achieve remote code execution in Grav CMS versions prior to 2.0.13 by exploiting improper input validation in the Flex Objects plugin to upload and execute arbitrary PHP files.
date: "2026-08-14T14:12:10Z"
lastmod: "2026-08-25T04:06:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - rce
  - ssti
  - cms
  - privilege-escalation
  - web-application
  - remote-code-execution
  - cve-2026-75827
vendors:
  - getgrav
products:
  - Grav CMS (< 2.0.13)
  - Grav (< 2.0.14)
  - Grav
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grav CMS before 2.0.13 contains a remote code execution vulnerability in the Flex Objects plugin settings validation that allows authenticated users to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can bypass routine name validation by using array notation instead of string notation, call the unZip routine with a malicious archive, and write PHP files to the web root for execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Grav CMS before 2.0.13 contains a server-side template injection vulnerability in email-action parameters that allows low-privileged page editors to execute arbitrary operating-system commands.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A delegated admin.users operator can save a group with access[admin][super]=true to escalate to super-admin.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers ... can invoke the error_log function through a data directive to append PHP payloads to web-accessible files, achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-72819
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72819
  - https://github.com/getgrav/grav/security/advisories/GHSA-r94f-hx44-8jqf
  - https://www.vulncheck.com/advisories/grav-cms-before-remote-code-execution-via-zip-upload
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72827
  - https://github.com/getgrav/grav/security/advisories/GHSA-xx48-97m4-h7qm
  - https://www.vulncheck.com/advisories/grav-cms-before-remote-code-execution-via-twig
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75837
  - https://github.com/getgrav/grav/security/advisories/GHSA-xhfv-7758-r9hx
  - https://www.vulncheck.com/advisories/grav-before-privilege-escalation-via-group-access-field
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75827
  - https://github.com/getgrav/grav/security/advisories/GHSA-f8wv-xp27-6gq7
  - https://www.vulncheck.com/advisories/grav-before-arbitrary-file-write-via-error-log
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75828
  - https://github.com/getgrav/grav/security/advisories/GHSA-vfmf-q6x9-cw96
  - https://www.vulncheck.com/advisories/grav-before-stored-xss-via-detectxss-quote-bypass
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56709
  - https://github.com/getgrav/grav/security/advisories/GHSA-69vf-mjxw-x79j
  - https://www.vulncheck.com/advisories/grav-before-host-header-injection-via-sendinvitationemail
rules:
  - title: Detect CVE-2026-72827 Exploitation Attempt
    description: Detects potential SSTI attempts in Grav CMS email parameters by identifying Twig syntax in HTTP POST form submissions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-56709 Exploitation - Anomalous Host Header in Web Requests
    description: Detects potential host header injection attempts where the Host header does not match the expected production domain.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Grav CMS to version 2.0.13
      owner: IT Operations
      due: 24h
      evidence: Source states versions before 2.0.13 are affected.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to administrative interfaces
      owner: IT Operations
      addresses: CVE-2026-72819
      evidence: Exploitation requires authenticated access.
updates:
  - at: "2026-08-14T14:12:24Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-72827 Exploitation Attempt'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72827
  - at: "2026-08-18T12:51:34Z"
    level: L2
    summary: added coverage for Grav (< 2.0.14)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75837
  - at: "2026-08-18T12:53:06Z"
    level: L2
    summary: added coverage for Grav
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75827
  - at: "2026-08-18T12:53:14Z"
    level: L2
    summary: added coverage for Grav
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75828
  - at: "2026-08-25T04:06:19Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-56709 Exploitation - Anomalous Host Header in Web Requests'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-56709
---

Grav CMS versions prior to 2.0.13 contain a critical vulnerability in the Flex Objects plugin (CVE-2026-72819) that facilitates remote code execution. The vulnerability stems from insufficient validation of plugin settings during the handling of ZIP archive uploads. Authenticated attackers can bypass security checks by manipulating input parameters, specifically by utilizing array notation instead of the expected string notation. This technique allows an attacker to manipulate the underlying routine name validation, successfully invoking the unZip routine with a crafted, malicious archive. By doing so, the attacker can extract arbitrary PHP files directly into the web root, which can subsequently be executed by the web server. This vulnerability allows for full code execution in the context of the web application user, posing a significant risk to the integrity and confidentiality of the host environment. Defenders should prioritize patching to version 2.0.13 or later.

## Attack Chain

1. Attacker gains authenticated access to the Grav CMS administrative interface or another area allowing interaction with the Flex Objects plugin.
2. Attacker prepares a ZIP archive containing a web shell or malicious PHP script intended for execution on the server.
3. Attacker initiates an upload process via the Flex Objects plugin, intercepting the request to modify input parameters.
4. Attacker replaces standard string-based input with array notation in the request to bypass the plugin's routine name validation filters.
5. The server-side validation logic fails to correctly parse the array notation, incorrectly validating the input and proceeding to the internal unZip routine.
6. The unZip routine processes the attacker-supplied malicious archive and extracts the contained PHP files into a directory accessible within the web root.
7. Attacker navigates to the location of the newly extracted PHP file in the web browser to trigger server-side execution.
8. Successful execution of the payload grants the attacker code execution, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-72819 results in complete remote code execution on the server hosting the Grav CMS installation. This level of access typically leads to total compromise of the application, including the ability to read or modify sensitive data, install further persistent backdoors, and move laterally within the network. The scope of impact is confined to organizations utilizing vulnerable versions of Grav CMS prior to 2.0.13.

## Recommendation

* Immediately update all instances of Grav CMS to version 2.0.13 or later to remediate CVE-2026-72819.
* Audit web server logs for suspicious POST requests targeting Flex Objects plugin endpoints that contain array notation (e.g., brackets like `[]` or nested array structures) in the request parameters.
* Restrict access to administrative and plugin-upload functionality to trusted internal IP ranges or VPN-only access to prevent exploitation by external, authenticated attackers.
* Monitor the web directory for the creation of unexpected `.php` files, particularly those uploaded through the web interface, as indicated by file access or modification logs.
