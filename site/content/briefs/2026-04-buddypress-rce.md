---
title: BuddyPress Xprofile Custom Fields Type 2.6.3 Remote Code Execution via Arbitrary File Deletion
slug: 2026-04-buddypress-rce
description: CVE-2018-25308 is a remote code execution vulnerability in BuddyPress Xprofile Custom Fields Type 2.6.3 that allows authenticated users to delete arbitrary files on the server by manipulating POST parameters.
date: "2026-04-29T20:16:26Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - rce
  - file-deletion
  - wordpress
products:
  - BuddyPress Xprofile Custom Fields Type
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2018-25308
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25308
  - http://lenonleite.com.br/
  - https://www.exploit-db.com/exploits/44432
  - https://www.vulncheck.com/advisories/buddypress-xprofile-custom-fields-type-remote-code-execution
rules:
  - title: Detect BuddyPress Arbitrary File Deletion Attempt via POST Parameter Manipulation
    description: Detects attempts to exploit CVE-2018-25308 by monitoring POST requests to the profile update endpoint with manipulated file paths in 'field_hiddenfile' or 'field_deleteimg' parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect BuddyPress Xprofile Field Manipulation (Alternative)
    description: Detects attempts to manipulate BuddyPress Xprofile fields by looking for specific keywords associated with file deletion attempts in POST data.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

BuddyPress Xprofile Custom Fields Type 2.6.3 is vulnerable to a remote code execution vulnerability, identified as CVE-2018-25308. This flaw enables authenticated users to execute arbitrary code on the server by deleting arbitrary files. The attack involves manipulating unescaped POST parameters, specifically `field_hiddenfile` and `field_deleteimg`, during profile editing actions. Successful exploitation allows attackers to unlink files from the server, potentially disrupting services or gaining unauthorized access. This vulnerability was published on 2026-04-29 and poses a significant threat to BuddyPress installations that have not applied the necessary patches.

## Attack Chain

1. An attacker authenticates to a BuddyPress site running the vulnerable Xprofile Custom Fields Type 2.6.3 plugin.
2. The attacker navigates to their profile editing page.
3. The attacker crafts a malicious HTTP POST request to the profile update endpoint.
4. Within the POST request, the `field_hiddenfile` and `field_deleteimg` parameters are manipulated to point to arbitrary files on the server.
5. The server-side script processes the crafted POST request without proper sanitization or validation of the file paths.
6. The `unlink()` function or an equivalent file deletion function is called with the attacker-controlled file paths.
7. The targeted files are deleted from the server file system.
8. The attacker can potentially delete critical system files or web application files, leading to remote code execution or denial of service.

## Impact

Successful exploitation of CVE-2018-25308 allows authenticated attackers to delete arbitrary files on the server. This can lead to a denial-of-service condition if critical system files are removed. The vulnerability can also potentially lead to remote code execution if the attacker is able to delete and replace executable files or inject malicious code into configuration files. While the number of victims is unknown, all BuddyPress installations using the vulnerable plugin are susceptible.

## Recommendation

*   Apply any available patches or updates for BuddyPress Xprofile Custom Fields Type to address CVE-2018-25308.
*   Implement input validation and sanitization on the server-side to prevent manipulation of file paths in POST parameters.
*   Monitor web server logs for suspicious POST requests targeting the profile update endpoint with unusual `field_hiddenfile` and `field_deleteimg` parameter values (reference the attack chain).
*   Deploy the Sigma rule provided to detect exploitation attempts based on the manipulation of specific POST parameters (reference the Sigma rule).
