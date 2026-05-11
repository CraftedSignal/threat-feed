---
title: Multiple Vulnerabilities in Mozilla Products Leading to Arbitrary Code Execution
slug: 2026-05-mozilla-vulns
description: Multiple vulnerabilities in Mozilla Firefox and Thunderbird products can lead to arbitrary code execution and unspecified security issues if the products are not updated to the latest versions.
date: "2026-05-11T12:07:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*
  - cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*
  - cpe:2.3:a:mozilla:thunderbird:*:*:*:*:esr:*:*:*
  - cpe:2.3:a:mozilla:thunderbird:*:*:*:*:-:*:*:*
tags:
  - vulnerability
  - arbitrary code execution
  - mozilla
vendors:
  - Mozilla
products:
  - Firefox ESR
  - Firefox
  - Thunderbird ESR
  - Thunderbird
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-8090
    cvss: 7.3
    epss: 0.00016
  - id: CVE-2026-8091
    cvss: 9.8
    epss: 0.00019
  - id: CVE-2026-8092
    cvss: 8.1
    epss: 0.00019
  - id: CVE-2026-8093
    cvss: 8.1
    epss: 0.00014
  - id: CVE-2026-8094
    cvss: 9.8
    epss: 0.00015
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0555/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-40/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-41/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-42/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-43/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-44/
  - https://www.cve.org/CVERecord?id=CVE-2026-8090
  - https://www.cve.org/CVERecord?id=CVE-2026-8091
  - https://www.cve.org/CVERecord?id=CVE-2026-8092
  - https://www.cve.org/CVERecord?id=CVE-2026-8093
  - https://www.cve.org/CVERecord?id=CVE-2026-8094
rules:
  - title: Detect Firefox Crash Report Generation
    description: Detects the generation of crash reports by Firefox, which could indicate a vulnerability exploitation attempt related to CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Crash Report Generation
    description: Detects the generation of crash reports by Thunderbird, which could indicate a vulnerability exploitation attempt related to CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 11, 2026, CERT-FR published an advisory regarding multiple vulnerabilities found in Mozilla products, specifically Firefox and Thunderbird. These vulnerabilities can be exploited by an attacker to achieve arbitrary code execution, as well as cause other unspecified security issues on a targeted system. The affected products include Firefox ESR versions prior to 115.35.2 and 140.10.2, Firefox versions prior to 150.0.2, Thunderbird ESR versions prior to 140.10.2, and Thunderbird versions prior to 140.10.2 and 150.0.2. It is recommended that users update to the latest versions to mitigate these risks. The vulnerabilities are tracked by CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.

## Attack Chain

1.  The attacker identifies a vulnerable Firefox or Thunderbird instance.
2.  The attacker crafts a malicious web page or email containing the exploit.
3.  The user opens the malicious web page in Firefox or views the email in Thunderbird.
4.  The exploit triggers a vulnerability, such as a memory corruption issue.
5.  The attacker gains arbitrary code execution on the user's machine.
6.  The attacker installs malware or performs other malicious actions.

## Impact

Successful exploitation of these vulnerabilities can lead to arbitrary code execution on the victim's machine. This can allow an attacker to install malware, steal sensitive information, or perform other malicious activities. Given the widespread use of Firefox and Thunderbird, a large number of users could be affected if these vulnerabilities are not addressed.

## Recommendation

*   Upgrade Firefox ESR to version 115.35.2 or later to remediate CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
*   Upgrade Firefox to version 150.0.2 or later to remediate CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
*   Upgrade Thunderbird ESR to version 140.10.2 or later to remediate CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
*   Upgrade Thunderbird to version 150.0.2 or later to remediate CVE-2026-8090, CVE-2026-8091, CVE-2026-8092, CVE-2026-8093, and CVE-2026-8094.
