---
title: Arbitrary Code Execution in IBM Aspera Desktop App via DLL Hijacking
slug: 2026-07-aspera-dll-hijack
description: IBM Aspera Desktop App versions 1.0.5 through 1.0.19 are susceptible to arbitrary code execution through a DLL hijacking vulnerability during application start-up.
date: "2026-07-30T15:31:42Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - IBM
products:
  - Aspera Desktop App (1.0.5 through 1.0.19)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: IBM Aspera Desktop App 1.0.5 through 1.0.19 can allow arbitrary code execution by loading DLL files at start-up.
    confidence_band: high
cves:
  - id: CVE-2026-11980
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11980
  - https://www.ibm.com/support/pages/node/7280939
---

IBM Aspera Desktop App versions 1.0.5 through 1.0.19 contain a DLL hijacking vulnerability (CVE-2026-11980) that allows local attackers to achieve arbitrary code execution. The vulnerability stems from insecure library loading practices during the application start-up process, where the software may load malicious DLL files placed in search paths or application-adjacent directories. By convincing a user to run the application or by placing a malicious DLL in a writeable directory where the application resolves its dependencies, an attacker can execute arbitrary code within the context of the user running the Aspera Desktop App. This flaw is classified under CWE-242 due to the use of inherently dangerous functions for library loading.

## Attack Chain

1. Attacker identifies the installation directory of IBM Aspera Desktop App.
2. Attacker writes a malicious DLL file to a location within the application's search path or directory.
3. Attacker ensures the malicious DLL uses the same name as a legitimate DLL expected by the Aspera Desktop App.
4. User or system process triggers the execution of the IBM Aspera Desktop App.
5. The application performs its initialization sequence and attempts to load the expected library.
6. The application loads the malicious DLL instead of the legitimate library due to search order precedence.
7. Malicious code contained within the DLL is executed under the security context of the user running the application.

## Impact

Successful exploitation of CVE-2026-11980 allows an attacker to execute arbitrary code on the local system. This can lead to full system compromise, data theft, or persistence on the affected machine. The impact depends on the privileges of the user running the application; if a user with administrative rights launches the application, the attacker's code may execute with elevated privileges.

## Recommendation

1. Upgrade IBM Aspera Desktop App to a version released after 1.0.19 to remediate the insecure library loading logic.
2. Implement strict directory permissions on the application installation path to prevent unauthorized file writes by non-privileged users.
3. Deploy endpoint detection and response (EDR) solutions to monitor for unusual DLL loading events from application-specific directories.
4. Audit file integrity in program directories to detect the presence of unauthorized or renamed DLL files.
