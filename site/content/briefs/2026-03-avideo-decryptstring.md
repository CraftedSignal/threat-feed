---
title: WWBN AVideo Unauthenticated decryptString Vulnerability
slug: 2026-03-avideo-decryptstring
description: WWBN AVideo, up to version 26.0, contains an improper authentication vulnerability (CVE-2026-33512) in the API plugin's `decryptString` action, allowing unauthenticated users to decrypt publicly accessible ciphertext and potentially recover protected tokens/metadata.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-33512
  - avideo
  - improper-authentication
  - api-vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33512
  - https://github.com/WWBN/AVideo/commit/3fdeecef37bb88967a02ccc9b9acc8da95de1c13
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-mwjc-5j4x-r686
rules:
  - title: Detect AVideo Unauthenticated decryptString Request
    description: Detects unauthenticated requests to the AVideo decryptString API endpoint, indicative of CVE-2026-33512 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Public Ciphertext Access
    description: Detects access to the public ciphertext endpoint url2Embed.json.php which may be used to gather ciphertext for CVE-2026-33512 exploitation.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo is an open-source video platform. Versions up to and including 26.0 are vulnerable to an improper authentication issue within the API plugin. The `decryptString` action, intended for internal decryption processes, is exposed without any authentication requirements. Attackers can exploit this vulnerability to submit ciphertext, which is publicly accessible through endpoints like `view/url2Embed.json.php`, and receive the corresponding plaintext. Successful exploitation allows…
