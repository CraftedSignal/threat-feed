---
title: Authentication Bypass in SourceCodester Human Resource Management System
slug: 2026-10-sourcecodester-hrms-auth-bypass
description: A vulnerability in SourceCodester Human Resource Management System 1.0 allows remote attackers to bypass authentication through input manipulation in the session_start function.
date: "2026-10-13T06:33:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:human_resource_management_system:1.0:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Human Resource Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The manipulation of the argument role/pfimg/EmpId results in improper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-108972
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108972
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web access logs for requests to controller/employee.php involving role, pfimg, or EmpId parameters
      owner: SOC
      due: 24h
      evidence: Source document identifies controller/employee.php and specific arguments as the vector.
  mitigation_plan:
    - priority: immediate
      action: Implement strict input validation on role, pfimg, and EmpId parameters in controller/employee.php
      owner: IT Operations
      addresses: CVE-2026-108972
      evidence: NVD vulnerability disclosure
---

A critical authentication vulnerability exists in SourceCodester Human Resource Management System 1.0. The flaw resides within the session_start function located in the controller/employee.php file of the Employee Endpoint component. An attacker can perform remote authentication bypass by manipulating the role, pfimg, or EmpId input arguments. Because the exploit code for this vulnerability has been disclosed publicly, there is an increased risk of exploitation by remote threat actors targeting HR management platforms. Defenders should prioritize auditing web application logs for unauthorized access attempts targeting the identified controller file and ensure that input validation is enforced for all session-related parameters.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to bypass session management, effectively gaining unauthorized access to the application as a legitimate user. This can lead to the compromise of sensitive employee data managed within the HR system, potentially resulting in unauthorized data exfiltration or administrative configuration changes. The system remains vulnerable if the component is deployed in its default configuration without additional hardening or patching of the controller logic.

## Recommendation

Prioritize the implementation of input validation and sanitization for the role, pfimg, and EmpId parameters within controller/employee.php. Monitor web server logs for anomalous POST or GET requests targeting the employee controller that contain unusual characters or unexpected data formats in these parameters. Given the availability of public exploit code, verify all active sessions for deviations from expected administrative patterns.
