---
title: Multiple Vulnerabilities in Rapid7 Velociraptor
slug: 2026-05-rapid7-velociraptor-vulns
description: Multiple vulnerabilities in Rapid7 Velociraptor could allow an attacker to perform a denial-of-service attack or disclose sensitive information.
date: "2026-05-06T10:41:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
vendors:
  - Rapid7
products:
  - Velociraptor
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1368
rules:
  - title: Detect Suspicious HTTP Request to Velociraptor Server
    description: Detects potential exploitation attempts by monitoring HTTP requests to the Velociraptor server with abnormal URI length.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Velociraptor Process Crash
    description: Detects potential exploitation attempts leading to a denial-of-service by monitoring for unexpected Velociraptor process terminations.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in Rapid7 Velociraptor. Successful exploitation of these vulnerabilities could allow an attacker to perform a denial-of-service (DoS) attack, potentially disrupting the availability of the Velociraptor service. Additionally, these vulnerabilities could lead to the disclosure of sensitive information, potentially compromising confidential data managed by Velociraptor. Defenders should apply appropriate mitigations and monitor for suspicious activity related to Velociraptor deployments.

## Attack Chain

1.  The attacker identifies a vulnerable Rapid7 Velociraptor instance accessible over the network.
2.  The attacker crafts a malicious request targeting a specific endpoint known to be vulnerable to a DoS attack.
3.  The Velociraptor server processes the malicious request, leading to resource exhaustion or a crash.
4.  The attacker exploits a separate vulnerability that allows for unauthorized access to sensitive information stored within Velociraptor.
5.  The attacker leverages crafted queries or API calls to extract sensitive data, such as configuration details, user credentials, or forensic artifacts.
6.  The attacker exfiltrates the stolen data to an external server under their control.

## Impact

Successful exploitation of these vulnerabilities can result in a denial of service, disrupting the functionality of Rapid7 Velociraptor. The disclosure of sensitive information could lead to further compromise, including unauthorized access to systems monitored by Velociraptor. The impact will vary depending on the specific vulnerabilities exploited and the sensitivity of the data exposed.

## Recommendation

*   Investigate and patch the Rapid7 Velociraptor deployment with the latest security updates provided by Rapid7 to mitigate the reported vulnerabilities.
*   Deploy the Sigma rules below to detect potential exploitation attempts targeting Rapid7 Velociraptor within your environment.
*   Monitor web server logs for suspicious requests patterns targeting the Rapid7 Velociraptor web interface (logsource: webserver).
