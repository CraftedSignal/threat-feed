---
title: Unauthenticated Deserialization Vulnerability in CentreStack
slug: 2026-07-centrestack-deserialization
description: An unauthenticated deserialization vulnerability in CentreStack allows remote attackers to create unauthorized local user accounts by sending crafted XML payloads to specific API endpoints.
date: "2026-07-30T13:40:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - deserialization
  - remote-code-execution
vendors:
  - Gladinet
products:
  - CentreStack (< 17.3)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CentreStack before 17.3 contains an unauthenticated deserialization vulnerability in GSNamespace.dll that allows unauthenticated attackers to create arbitrary local OS user accounts.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: Attackers can send a malicious StorageConfigure parameter... causing GladinetCloudMonitor.exe to invoke the NetUserAdd Windows API with attacker-controlled credentials.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54365
---

CentreStack versions prior to 17.3 contain a critical deserialization vulnerability residing in GSNamespace.dll. This vulnerability stems from improper handling of base64-encoded XML input provided to exposed web API endpoints. Unauthenticated remote attackers can leverage this flaw to trigger the InternalImportAdUserByUPN() method within the GladinetCloudMonitor.exe process. By supplying a malicious 'StorageConfigure' parameter, an attacker can coerce the application to invoke the Windows NetUserAdd API, resulting in the unauthorized creation of local OS user accounts. Furthermore, the attacker can influence filesystem operations, potentially leading to arbitrary directory creation on the host server. This vulnerability is significant as it provides a pathway for initial access, persistence, and privilege escalation on systems running CentreStack in a Windows environment.

## Attack Chain

1. The attacker identifies an internet-facing instance of CentreStack running version < 17.3.
2. The attacker crafts a malicious base64-encoded XML payload containing the 'StorageConfigure' parameter.
3. The attacker submits the payload via an HTTP POST request to exposed API endpoints, specifically jsonimportuserbyupn, jsonimportuserbyupnex, or japiimportuserbyupn.
4. The GSNamespace.dll component deserializes the malicious XML input without proper validation.
5. The application triggers the InternalImportAdUserByUPN() method, which is serviced by the GladinetCloudMonitor.exe process.
6. The process invokes the native Windows NetUserAdd API using the parameters provided in the deserialized input.
7. A new, unauthorized local user account is created on the Windows host operating system.
8. The attacker achieves persistence or privilege escalation through the newly created account.

## Impact

Successful exploitation allows unauthenticated attackers to gain administrative-level control over the underlying Windows host by creating arbitrary local accounts. This bypasses authentication mechanisms, facilitating unauthorized access to the application and the host server. Given the nature of CentreStack as a file management and remote access solution, compromised instances could lead to full exfiltration of stored organizational data or provide a persistent foothold within the internal network.

## Recommendation

1. Upgrade all CentreStack installations to version 17.3 or later immediately to patch CVE-2026-54365.
2. Restrict access to the CentreStack web interface and its associated API endpoints to authorized networks only using IP whitelisting at the network perimeter.
3. Monitor Windows security event logs (Event ID 4720) for the creation of new local user accounts, particularly those originating from the GladinetCloudMonitor.exe process or unexpected system accounts.
4. Audit filesystem activity for unusual directory creation in sensitive paths initiated by the Gladinet service user account.
