---
title: pyLoad Arbitrary Code Execution via Malicious Session Deserialization
slug: 2026-04-pyload-rce
description: pyLoad is vulnerable to arbitrary code execution via an unprotected `storage_folder` configuration option, allowing an attacker with `SETTINGS` and `ADD` permissions to write a malicious pickle payload to the Flask session store and execute arbitrary code upon subsequent HTTP requests.
date: "2026-04-04T06:43:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - pyLoad
  - rce
  - pickle
  - deserialization
  - webserver
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-33509
    cvss: 7.5
    epss: 0.00085
references:
  - https://github.com/advisories/GHSA-4744-96p5-mp2j
iocs:
  - type: url
    value: http://attacker.com/92912f771df217fb6fbfded6705dd47c
  - type: hash_md5
    value: 92912f771df217fb6fbfded6705dd47c
ioc_counts:
  hash_md5: 1
  url: 1
rules:
  - title: Suspicious pyLoad Storage Folder Modification
    description: Detects attempts to change the pyLoad storage_folder configuration to the Flask session directory, indicative of CVE-2026-35464 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1202
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: pyLoad Malicious Session Cookie Usage
    description: Detects HTTP requests with a pyload session cookie and a request to the root path, potentially indicating deserialization of a malicious session.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

pyLoad, a download manager, is susceptible to arbitrary code execution due to an insecure configuration option related to the storage folder. This vulnerability arises from the incomplete fix for CVE-2026-33509. Specifically, the `storage_folder` option is not included in the `ADMIN_ONLY_OPTIONS` set, which allows users with `SETTINGS` and `ADD` permissions to modify it. By redirecting downloads to the Flask filesystem session store, an attacker can plant a malicious pickle payload as a predictable session file. Subsequently, any HTTP request containing the corresponding crafted session cookie will trigger the deserialization of the payload, resulting in arbitrary code execution. This issue affects pyLoad versions up to and including 0.5.0b3. The observed exploitation involves manipulating the download directory to write malicious files into the Flask session store, ultimately leading to code execution on the host.

## Attack Chain

1.  An attacker gains a non-admin user account with both `SETTINGS` and `ADD` permissions in pyLoad.
2.  The attacker uses the `/api/set_config_value` endpoint to modify the `storage_folder` option, setting its value to the Flask session store directory: `/tmp/pyLoad/flask`. This bypasses existing path restrictions.
3.  The attacker calculates the target session filename by computing the MD5 hash of the string "session:ATTACKER_SESSION_ID".
4.  The attacker hosts a malicious pickle payload (e.g., `92912f771df217fb6fbfded6705dd47c`) on a remote server.
5.  The attacker uses the `/api/add_package` endpoint to add a download package. The download link points to the hosted malicious pickle payload on the attacker's server: `http://attacker.com/92912f771df217fb6fbfded6705dd47c`. The `dest` parameter specifies where to store the downloaded file.
6.  pyLoad downloads the malicious pickle payload and saves it to the Flask session store directory, naming it according to the MD5 hash calculated earlier.
7.  The attacker crafts an HTTP request to the pyLoad server, including a cookie named `pyload_session_{port}` with the value `ATTACKER_SESSION_ID`.  The port number is derived from the pyLoad configuration.
8.  Upon receiving the request with the crafted cookie, Flask attempts to load the session data from the corresponding file. The `cachelib` library deserializes the malicious pickle payload using `pickle.load()`, triggering arbitrary code execution.

## Impact

Successful exploitation allows a non-admin user with SETTINGS and ADD permissions to achieve arbitrary code execution as the pyload service user. This grants the attacker the ability to execute arbitrary commands, read environment variables (potentially exposing API keys and credentials), access the filesystem (including download history and user databases), and potentially pivot to other network resources. The vulnerability requires no authentication to trigger the final stage of exploitation, increasing its severity and potential impact.

## Recommendation

*   Deploy the following Sigma rule to detect attempts to modify the `storage_folder` configuration option to point to the Flask session directory (`/tmp/pyLoad/flask`): `Suspicious pyLoad Storage Folder Modification`.
*   Apply the suggested fix by adding `storage_folder` to the `ADMIN_ONLY_OPTIONS` set in the pyLoad configuration to prevent non-admin users from modifying it.
*   Block the malicious URLs used to deliver the pickle payload, specifically `http://attacker.com/92912f771df217fb6fbfded6705dd47c`, at your network perimeter.
*   Monitor for HTTP requests containing the crafted session cookie (`pyload_session_{port}=ATTACKER_SESSION_ID`), using a webserver or proxy log source, as it triggers the final stage of the attack.
