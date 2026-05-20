---
title: Multiple Vulnerabilities in Mozilla Products Lead to Potential RCE and Privilege Escalation
slug: 2026-05-mozilla-vulns
description: Multiple vulnerabilities in Mozilla Firefox ESR, Firefox, Firefox for iOS, and Thunderbird products can lead to arbitrary code execution, privilege escalation, and remote denial of service.
date: "2026-05-20T14:09:33Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*
  - cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*
  - cpe:2.3:a:mozilla:thunderbird:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - privilege-escalation
  - dos
vendors:
  - Mozilla
products:
  - Firefox ESR (versions prior to 115.36)
  - Firefox ESR (versions prior to 140.11)
  - Firefox for iOS (versions prior to 151.0)
  - Firefox (versions prior to 151)
  - Thunderbird (versions prior to 140.11)
  - Thunderbird (versions prior to 151)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-8706
    cvss: 6.5
  - id: CVE-2026-8947
    cvss: 7.3
  - id: CVE-2026-8948
    cvss: 9.1
  - id: CVE-2026-8951
    cvss: 6.5
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0615/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-46/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-47/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-48/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-49/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-50/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-51/
  - https://www.cve.org/CVERecord?id=CVE-2026-8388
  - https://www.cve.org/CVERecord?id=CVE-2026-8391
  - https://www.cve.org/CVERecord?id=CVE-2026-8401
  - https://www.cve.org/CVERecord?id=CVE-2026-8706
  - https://www.cve.org/CVERecord?id=CVE-2026-8945
  - https://www.cve.org/CVERecord?id=CVE-2026-8946
  - https://www.cve.org/CVERecord?id=CVE-2026-8947
  - https://www.cve.org/CVERecord?id=CVE-2026-8948
  - https://www.cve.org/CVERecord?id=CVE-2026-8949
  - https://www.cve.org/CVERecord?id=CVE-2026-8950
  - https://www.cve.org/CVERecord?id=CVE-2026-8951
  - https://www.cve.org/CVERecord?id=CVE-2026-8952
  - https://www.cve.org/CVERecord?id=CVE-2026-8953
  - https://www.cve.org/CVERecord?id=CVE-2026-8954
  - https://www.cve.org/CVERecord?id=CVE-2026-8955
  - https://www.cve.org/CVERecord?id=CVE-2026-8956
  - https://www.cve.org/CVERecord?id=CVE-2026-8957
  - https://www.cve.org/CVERecord?id=CVE-2026-8958
  - https://www.cve.org/CVERecord?id=CVE-2026-8959
  - https://www.cve.org/CVERecord?id=CVE-2026-8960
  - https://www.cve.org/CVERecord?id=CVE-2026-8961
  - https://www.cve.org/CVERecord?id=CVE-2026-8962
  - https://www.cve.org/CVERecord?id=CVE-2026-8963
  - https://www.cve.org/CVERecord?id=CVE-2026-8964
  - https://www.cve.org/CVERecord?id=CVE-2026-8965
  - https://www.cve.org/CVERecord?id=CVE-2026-8966
  - https://www.cve.org/CVERecord?id=CVE-2026-8967
  - https://www.cve.org/CVERecord?id=CVE-2026-8968
  - https://www.cve.org/CVERecord?id=CVE-2026-8969
  - https://www.cve.org/CVERecord?id=CVE-2026-8970
  - https://www.cve.org/CVERecord?id=CVE-2026-8971
  - https://www.cve.org/CVERecord?id=CVE-2026-8972
  - https://www.cve.org/CVERecord?id=CVE-2026-8973
  - https://www.cve.org/CVERecord?id=CVE-2026-8974
  - https://www.cve.org/CVERecord?id=CVE-2026-8975
rules:
  - title: Detect Potential Mozilla Exploitation via Suspicious User-Agent
    description: Detects potential exploitation attempts targeting Mozilla products based on unusual User-Agent strings.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Mozilla Product Crash Reporting with Potential Exploit Data
    description: Detects crash reporting events from Mozilla products that include suspicious data potentially related to exploit attempts.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 20, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting Mozilla products, including Firefox ESR, Firefox, Firefox for iOS, and Thunderbird. These vulnerabilities can potentially allow an attacker to perform arbitrary code execution, elevate privileges, and cause a remote denial of service. The advisory highlights the need for users and organizations to apply the necessary patches to mitigate the risks associated with these vulnerabilities. The specific versions affected are Firefox ESR versions prior to 115.36 and 140.11, Firefox for iOS versions prior to 151.0, Firefox versions prior to 151, and Thunderbird versions prior to 140.11 and 151.

## Attack Chain

1.  Attacker identifies a vulnerable Mozilla product (Firefox, Thunderbird, etc.) running an unpatched version.
2.  The attacker crafts a malicious webpage or email leveraging one of the disclosed vulnerabilities (CVE-2026-8388, CVE-2026-8391, CVE-2026-8401, CVE-2026-8706, CVE-2026-8945, CVE-2026-8946, CVE-2026-8947, CVE-2026-8948, CVE-2026-8949, CVE-2026-8950, CVE-2026-8951, CVE-2026-8952, CVE-2026-8953, CVE-2026-8954, CVE-2026-8955, CVE-2026-8956, CVE-2026-8957, CVE-2026-8958, CVE-2026-8959, CVE-2026-8960, CVE-2026-8961, CVE-2026-8962, CVE-2026-8963, CVE-2026-8964, CVE-2026-8965, CVE-2026-8966, CVE-2026-8967, CVE-2026-8968, CVE-2026-8969, CVE-2026-8970, CVE-2026-8971, CVE-2026-8972, CVE-2026-8973, CVE-2026-8974, CVE-2026-8975).
3.  The victim interacts with the malicious content (e.g., visits the webpage or opens the email).
4.  The vulnerability is triggered, allowing the attacker to execute arbitrary code within the context of the application.
5.  The attacker leverages the initial code execution to escalate privileges on the system.
6.  The attacker gains control of the system, enabling them to perform various malicious activities, such as data theft or further exploitation.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access to sensitive information, compromise of the affected system, and potential disruption of services. Given the widespread use of Mozilla products, a large number of users and organizations are potentially at risk. The consequences include data breaches, financial losses, and reputational damage.

## Recommendation

*   Immediately patch Firefox ESR versions prior to 115.36 and 140.11, Firefox for iOS versions prior to 151.0, Firefox versions prior to 151, and Thunderbird versions prior to 140.11 and 151, as identified in the advisory and the affected products list.
*   Monitor web server logs for unusual activity that may indicate exploitation attempts targeting these vulnerabilities; correlate with endpoint logs to confirm successful exploitation and lateral movement.
*   Deploy the provided Sigma rule to detect potential exploitation of these vulnerabilities in web traffic.
