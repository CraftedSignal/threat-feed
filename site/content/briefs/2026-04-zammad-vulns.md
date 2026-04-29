---
title: Multiple Vulnerabilities in Zammad
slug: 2026-04-zammad-vulns
description: Multiple vulnerabilities in Zammad allow a remote attacker to execute arbitrary code, bypass security measures, disclose sensitive information, and perform cross-site scripting attacks.
date: "2026-04-09T08:09:17Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - zammad
  - vulnerability
  - code execution
  - xss
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1000
rules:
  - title: Detect Potential Zammad Code Execution via Web Request
    description: Detects potential attempts to exploit code execution vulnerabilities in Zammad via suspicious web requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Zammad XSS Attempt via URI
    description: Detects potential XSS attempts in Zammad via common JavaScript injection strings in the URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Zammad, a web-based open-source helpdesk and customer support system, is susceptible to multiple vulnerabilities. A remote, unauthenticated attacker may exploit these flaws to achieve arbitrary code execution, bypass security restrictions, conduct information disclosure, and launch cross-site scripting (XSS) attacks against users of the application. Successful exploitation of these vulnerabilities poses a significant risk to the confidentiality, integrity, and availability of the Zammad instance and its underlying data. This can lead to data breaches, unauthorized access, and disruption of critical customer support services. Defenders should prioritize patching and implementing mitigations to prevent exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable Zammad instance accessible over the network.
2.  The attacker exploits a vulnerability that allows bypassing authentication or authorization controls.
3.  The attacker leverages a code execution vulnerability to inject and execute malicious code on the Zammad server.
4.  The attacker utilizes the executed code to gain a persistent foothold on the system.
5.  The attacker exploits an information disclosure vulnerability to retrieve sensitive data, such as database credentials or API keys.
6.  The attacker uses the stolen credentials to access other internal resources or escalate privileges within the Zammad application.
7.  The attacker injects malicious JavaScript code into the Zammad application via a Cross-Site Scripting (XSS) vulnerability.
8.  When other users interact with the injected code, the attacker can steal session cookies or perform actions on their behalf, potentially leading to full account compromise.

## Impact

Successful exploitation of the vulnerabilities in Zammad can lead to complete compromise of the helpdesk system and the exposure of sensitive customer data. Depending on the organization, this could affect thousands of customers and result in significant financial and reputational damage. Sectors relying heavily on customer support, such as technology, retail, and finance, are particularly at risk. An attacker could also leverage a compromised Zammad instance to launch further attacks against internal systems or customers.

## Recommendation

*   Inspect web server logs for unusual activity and potential exploitation attempts targeting the Zammad application.
*   Deploy the Sigma rule to detect potential exploitation of code execution vulnerabilities via web requests.
*   Implement a web application firewall (WAF) rule to filter out malicious requests attempting to exploit known Zammad vulnerabilities.
