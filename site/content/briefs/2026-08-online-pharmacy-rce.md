---
title: Unrestricted File Upload Vulnerability in itsourcecode Online Pharmacy System
slug: 2026-08-online-pharmacy-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-78245) exists in itsourcecode Online Pharmacy System 1.0 due to improper file validation within the user registration process.
date: "2026-08-24T11:56:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - remote-code-execution
  - cve-2026-78245
vendors:
  - itsourcecode
products:
  - Online Pharmacy System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A flaw has been found in itsourcecode Online Pharmacy System 1.0... Executing a manipulation of the argument photo can lead to unrestricted upload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attack may be launched remotely... Executing a manipulation of the argument photo can lead to unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-78245
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78245
  - https://vuldb.com/vuln/394595
  - https://github.com/microwaveabi/vul/issues/47
rules:
  - title: Detect CVE-2026-78245 Exploitation - Unrestricted File Upload Attempt
    description: Detects potential exploitation attempts of CVE-2026-78245 by monitoring HTTP POST requests to register.php with suspicious file extensions in the 'photo' argument
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
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rules to block malicious file extensions in registration requests
      owner: SOC
      due: 24h
      evidence: CVE-2026-78245 vulnerability documentation
  hunt_leads:
    - lead: Search web logs for POST requests to /all_users/register.php followed by GET requests to non-image files in the upload directory
      technique_id: T1190
      data_needed:
        - Web access logs
        - File system modification logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit involves arbitrary file upload via register.php
  mitigation_plan:
    - priority: immediate
      action: Disable access to the Online Pharmacy System 1.0 application
      owner: IT Operations
      addresses: CVE-2026-78245
      evidence: High CVSS score and public exploit availability
---

A security vulnerability identified as CVE-2026-78245 affects the itsourcecode Online Pharmacy System version 1.0. The vulnerability is located within the 'all_users/register.php' file, specifically in the component responsible for user registration. An attacker can manipulate the 'photo' argument passed to the 'move_uploaded_file' function, allowing for the unrestricted upload of arbitrary files to the server. Because the application fails to adequately validate or restrict the file types processed by this function, a remote, unauthenticated attacker could upload malicious scripts, such as web shells, leading to remote code execution. This vulnerability is highly critical due to the lack of required authentication, allowing exploitation by any remote actor with network access to the target application. Public exploit code has been reported, making this an immediate risk to organizations running this specific version of the software.

## Attack Chain

1. Attacker performs reconnaissance to identify systems running itsourcecode Online Pharmacy System 1.0.
2. Attacker navigates to the public user registration page located at /all_users/register.php.
3. Attacker initiates a registration request, intercepting the HTTP request using a proxy tool.
4. Attacker modifies the 'photo' parameter in the POST request to point to a malicious file, such as a PHP web shell.
5. The application's 'move_uploaded_file' function processes the malicious request without validating the file extension or content.
6. The web server saves the attacker-supplied file into a directory accessible by the web root.
7. Attacker requests the newly uploaded file via the browser to trigger execution of the malicious script.
8. Attacker achieves remote command execution with the privileges of the web server service account.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to gain remote code execution on the underlying server. This can lead to full system compromise, data theft, ransomware deployment, or use of the server as a pivot point for further lateral movement within the target organization's network. Given the nature of the application as a pharmacy management system, the potential exposure of sensitive patient and operational data is significant.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Deploy a web application firewall (WAF) rule to inspect and block requests to '/all_users/register.php' that contain suspicious file extensions (e.g., .php, .php5, .phtml) within the 'photo' parameter.
- Implement monitoring for new file creation events within the web directory where user-uploaded photos are stored.
- Audit the web server configuration to ensure that file execution permissions are restricted in user upload directories.
- Identify and decommission any production instances of 'Online Pharmacy System' 1.0 until a security patch is provided by the vendor.
