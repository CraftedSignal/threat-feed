---
title: CI4MS Theme Upload Zip Slip Vulnerability
slug: 2024-01-02-ci4ms-zip-slip
description: A critical vulnerability exists in ci4ms Theme::upload, where improper validation of ZIP archive entry names allows authenticated users with theme creation permissions to write files to arbitrary locations, leading to remote code execution.
date: "2024-01-02T12:00:00Z"
severities:
  - critical
tags:
  - zip-slip
  - rce
  - codeigniter
  - vulnerability
vendors:
  - composer
products:
  - ci4-cms-erp/ci4ms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-xv3r-vr59-95rg
rules:
  - title: Detect CI4MS Webshell Upload via Theme Exploit
    description: Detects the upload of a ZIP archive containing a PHP webshell with path traversal sequences via the CI4MS theme upload functionality.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Webshell Access After CI4MS Exploit
    description: Detects access to a PHP webshell uploaded via the CI4MS theme upload vulnerability. This rule identifies requests to 'shell.php' with a 'c' parameter for command execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The ci4ms application is vulnerable to a Zip Slip attack in its theme upload functionality. This vulnerability, present in versions prior to 0.31.5.0, allows an authenticated backend user with theme creation privileges to upload a specially crafted ZIP archive. Due to the lack of proper validation of entry names during extraction, the attacker can write files to arbitrary locations on the filesystem. This is achieved by including malicious path traversal sequences (e.g., `../../`) in the ZIP…
