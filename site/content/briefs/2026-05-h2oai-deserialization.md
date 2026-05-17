---
title: Deserialization Vulnerability in H2Oai H2O-3 (CVE-2026-8751)
slug: 2026-05-h2oai-deserialization
description: A deserialization vulnerability exists in h2oai's h2o-3 up to version 7402, specifically within the importBinaryModel function of the h2o-core/src/main/java/hex/Model.java file's JAR Handler component, allowing remote exploitation through manipulation.
date: "2026-05-17T12:17:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - rce
  - cve
vendors:
  - h2oai
products:
  - h2o-3 (<= 7402)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8751
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8751
rules:
  - title: Detect Deserialization Attempt in H2Oai H2O-3 (CVE-2026-8751)
    description: Detects CVE-2026-8751 exploitation — Attempts to exploit the deserialization vulnerability in H2Oai H2O-3 by detecting suspicious POST requests to the application with serialized Java objects.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect H2Oai H2O-3 importBinaryModel Function Access
    description: Detects access to the importBinaryModel function in H2Oai H2O-3, potentially indicating an attempt to exploit CVE-2026-8751.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A deserialization vulnerability, identified as CVE-2026-8751, has been discovered in h2oai's h2o-3, affecting versions up to 7402. The vulnerability resides within the `importBinaryModel` function in the `h2o-core/src/main/java/hex/Model.java` file, specifically in the JAR Handler component. This flaw allows remote attackers to perform manipulation that leads to deserialization, potentially allowing for arbitrary code execution. The exploit is publicly available, increasing the risk of exploitation. The vendor was contacted regarding this vulnerability but did not respond. Due to the ease of exploitation and potential impact, this vulnerability poses a significant risk to systems running affected versions of h2o-3.

## Attack Chain

1.  Attacker identifies a vulnerable h2o-3 instance running a version <= 7402.
2.  Attacker crafts a malicious serialized object designed to exploit the `importBinaryModel` function.
3.  Attacker sends a request to the vulnerable h2o-3 instance, providing the malicious serialized object to the `importBinaryModel` function.
4.  The `importBinaryModel` function attempts to deserialize the object.
5.  Due to the vulnerability, the deserialization process executes arbitrary code embedded within the malicious object.
6.  The attacker gains control of the h2o-3 instance, potentially with the privileges of the user running the application.
7.  The attacker can then use this access to pivot to other systems, exfiltrate data, or cause further damage.

## Impact

Successful exploitation of CVE-2026-8751 can lead to arbitrary code execution on the affected h2o-3 instance. This can result in complete system compromise, including the potential for data theft, system disruption, or further lateral movement within the network. Given the public availability of the exploit, organizations using vulnerable versions of h2o-3 are at immediate risk. The absence of a vendor response or patch exacerbates the situation, leaving organizations with limited options for remediation beyond mitigation strategies.

## Recommendation

*   Apply network access controls to restrict access to the h2o-3 service to only authorized users and systems.
*   Deploy the Sigma rule `Detect Deserialization Attempt in H2Oai H2O-3 (CVE-2026-8751)` to identify potential exploitation attempts in web server logs.
*   Monitor network traffic for unusual patterns that may indicate exploitation attempts, using network connection logs.
*   Implement input validation and sanitization measures to prevent the injection of malicious serialized objects.
