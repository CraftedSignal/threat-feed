---
title: Goshs File-Based ACL Authorization Bypass Vulnerability
slug: 2026-04-goshs-acl-bypass
description: Goshs is vulnerable to an authorization bypass (CVE-2026-40189) due to inconsistent enforcement of .goshs ACLs on state-changing routes, allowing an unauthenticated attacker to manipulate files within protected directories and bypass authentication barriers.
date: "2026-04-10T20:02:46Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - authorization bypass
  - acl
  - file upload
  - file deletion
  - CVE-2026-40189
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1211
    technique_name: Exploitation of Web Applications
references:
  - https://github.com/advisories/GHSA-wvhv-qcqf-f3cx
iocs:
  - type: url
    value: http://127.0.0.1:18091/protected/
  - type: url
    value: http://127.0.0.1:18091/protected/put-created.txt
  - type: url
    value: http://127.0.0.1:18091/protected/.goshs?delete
  - type: url
    value: http://127.0.0.1:18091/protected/secret.txt
ioc_counts:
  url: 4
rules:
  - title: Detect Goshs Unauthenticated .goshs Deletion
    description: Detects attempts to delete .goshs ACL files via the ?delete parameter, indicating a potential authorization bypass.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Goshs Unauthenticated PUT Request to Protected Directories
    description: Detects PUT requests to directories that should be protected by .goshs ACLs, indicating a potential authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Goshs Unauthenticated Directory Creation via mkdir
    description: Detects requests with the `?mkdir` parameter, indicating a potential authorization bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 3
---

The Goshs web server is susceptible to a critical authorization bypass (CVE-2026-40189) affecting versions up to and including 1.1.4 and v2.0.0-beta.3. The vulnerability stems from inconsistent enforcement of file-based ACLs defined by `.goshs` files. While the application correctly enforces authorization for reading and listing files, state-changing routes such as PUT, POST /upload, ?mkdir, and ?delete do not perform the same authorization checks. This allows unauthenticated attackers to upload, create, and delete files within directories that should be protected by authentication. The most severe impact arises from the ability to delete the `.goshs` file itself, thereby removing the authentication requirement and exposing previously protected content. This vulnerability undermines the intended security mechanisms of Goshs, posing a significant risk to data confidentiality, integrity, and availability.

## Attack Chain

1.  The attacker identifies a Goshs instance utilizing `.goshs` files for access control.
2.  The attacker sends an unauthenticated PUT request to upload a file to a protected directory, bypassing ACL checks via `httpserver/updown.go:18-60`. Example: `PUT /protected/put-created.txt`
3.  Alternatively, the attacker sends an unauthenticated multipart POST request to `/upload` endpoint to upload a file to a protected directory, bypassing ACL checks via `httpserver/updown.go:63-165`. Example: `POST /protected/upload`
4.  The attacker sends an unauthenticated request with the `?mkdir` parameter to create a directory within the protected directory, bypassing ACL checks via `httpserver/handler.go:901-937`. Example: `/?mkdir=new_directory`
5.  The attacker sends an unauthenticated request with the `?delete` parameter targeting the `.goshs` file within the protected directory, leveraging the vulnerable route in `httpserver/handler.go:679-698`. Example: `/.goshs?delete`
6.  The server deletes the `.goshs` file using `os.RemoveAll()`, effectively removing the access control restrictions for the directory.
7.  The attacker sends an unauthenticated request to access previously protected files, which are now accessible due to the absence of the `.goshs` file.
8.  The attacker gains unauthorized access to sensitive information and can perform further malicious actions, such as deleting or modifying critical files.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to bypass intended access controls in Goshs deployments. This can lead to unauthorized access to sensitive files, potentially exposing confidential information. Attackers can also create, modify, or delete files within protected directories, causing data corruption or service disruption. The ability to delete the `.goshs` file directly amplifies the impact, as it permanently removes the authentication barrier, affecting all previously protected content. This vulnerability poses a significant threat to the confidentiality, integrity, and availability of Goshs-hosted data.

## Recommendation

*   Apply the vendor-supplied patch or upgrade to a version of Goshs that addresses CVE-2026-40189.
*   Deploy the Sigma rule "Detect Goshs Unauthenticated .goshs Deletion" to your SIEM to detect attempts to remove `.goshs` ACL files via the `?delete` parameter.
*   Deploy the Sigma rule "Detect Goshs Unauthenticated PUT Request to Protected Directories" to detect unauthorized file uploads to protected directories.
*   Monitor web server logs for PUT, POST, and DELETE requests targeting directories containing `.goshs` files to identify potential exploitation attempts. (Log Source: webserver)
