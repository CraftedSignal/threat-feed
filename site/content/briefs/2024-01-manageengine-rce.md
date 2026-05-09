---
title: ManageEngine Applications Manager Authenticated RCE via File Upload (CVE-2020-14008)
slug: 2024-01-manageengine-rce
description: CVE-2020-14008 is an unrestricted file upload vulnerability in Zoho ManageEngine Applications Manager that allows an authenticated attacker to upload a malicious JAR file containing a reverse shell to achieve remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:-:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14000:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14010:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14020:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14030:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14040:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14050:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14060:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14070:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14071:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14072:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14073:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14080:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14090:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14100:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14110:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14120:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14130:*:*:*:*:*:*
  - cpe:2.3:a:zohocorp:manageengine_applications_manager:14.0:build14140:*:*:*:*:*:*
tags:
  - rce
  - file upload
  - manageengine
vendors:
  - Zoho
products:
  - ManageEngine Applications Manager
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1134
    technique_name: Access Token Manipulation
cves:
  - id: CVE-2020-14008
    cvss: 7.2
    epss: 0.46229
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-14008
  - https://www.exploit-db.com/exploits/48793
  - https://manageengine.co.uk/products/applications_manager/security-updates/security-updates-cve-2020-14008.html
rules:
  - title: Detects CVE-2020-14008 Exploitation — Malicious JAR Upload
    description: Detects CVE-2020-14008 exploitation — Suspicious JAR file upload to ManageEngine Applications Manager webserver
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2020-14008 Exploitation — Java Process in weblogic directory
    description: Detects CVE-2020-14008 exploitation — Java process execution from the weblogic directory
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

An authenticated remote code execution vulnerability exists in Zoho ManageEngine Applications Manager due to an unrestricted file upload (CVE-2020-14008). Successful exploitation allows attackers to execute arbitrary code on the system. The exploit involves authenticating to the application, identifying the installation directory, crafting a malicious Java class within a JAR file, uploading the JAR to a specific directory via directory traversal, and then triggering the execution of the uploaded code through the Weblogic credential test. Default credentials of "admin:admin", "admin:password", "administrator:administrator", and "guest:guest" may be leveraged to gain unauthorized access. This vulnerability affects multiple versions of ManageEngine Applications Manager.

## Attack Chain

1. Authenticate to ManageEngine Applications Manager using valid credentials (e.g., default credentials) to obtain a session cookie.
2. Enumerate the ManageEngine base installation directory.
3. Create a malicious Java class (e.g., `weblogic.jndi.Environment`) containing a reverse shell.
4. Compile the Java class into a JAR file (e.g., `weblogic.jar`) using `javac` and `jar`.
5. Upload the malicious JAR file to the `classes/weblogic/version8/` directory using directory traversal techniques. As a fallback, create a scheduled task to move the file.
6. Trigger the Weblogic credential test at the `/testCredential.do` endpoint.
7. The application loads and instantiates the malicious Java class.
8. The reverse shell within the JAR connects back to the attacker's listener, granting remote code execution.

## Impact

Successful exploitation allows the attacker to execute arbitrary code on the affected system, potentially leading to complete system compromise, data theft, and disruption of services. Organizations using ManageEngine Applications Manager are at risk. The exploitation could lead to lateral movement within the network and further compromise of sensitive data.

## Recommendation

*   Apply the security updates provided by ManageEngine to patch CVE-2020-14008 as detailed in the ManageEngine Advisory.
*   Deploy the Sigma rule for detecting JAR file uploads to the webserver log and tune for your environment.
*   Monitor process creation events for Java processes executing from the `classes/weblogic/version8/` directory, using the provided Sigma rule.
*   Enforce strong password policies and regularly audit user accounts to prevent the use of default credentials, as mentioned in the overview.
