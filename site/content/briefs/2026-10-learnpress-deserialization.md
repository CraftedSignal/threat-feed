---
title: 'CVE-2026-104736: PHP Object Injection in LearnPress WordPress Plugin'
slug: 2026-10-learnpress-deserialization
description: The LearnPress plugin for WordPress is vulnerable to unauthenticated PHP Object Injection via the 'checkout-email' parameter, allowing remote attackers to trigger insecure deserialization.
date: "2026-10-17T04:47:50Z"
lastmod: "2026-10-18T22:58:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:learnpress:learnpress:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=F33A2AF2-DC99-522B-8D64-AEDAEDAA70F5&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - php-deserialization
  - wordpress
  - cve-2026-104736
vendors:
  - WordPress
products:
  - LearnPress (<= 4.4.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this vulnerability by submitting a maliciously crafted serialized object via the 'checkout-email' parameter during the checkout AJAX action.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for unauthenticated attackers to inject a PHP Object... potentially leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-104736
    cvss: 9.8
    epss: 0.00438
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104736
  - https://sploitus.com/exploit?id=F33A2AF2-DC99-522B-8D64-AEDAEDAA70F5&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-104736 Exploitation Attempt
    description: Detects potential CVE-2026-104736 exploitation attempts by looking for serialized PHP object syntax in the checkout-email parameter of POST requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LearnPress to a version newer than 4.4.10
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104736 remediation
  hunt_leads:
    - lead: Search web server access logs for serialized object structures in the 'checkout-email' parameter
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known injection vector in LearnPress plugin
updates:
  - at: "2026-10-18T22:58:09Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=F33A2AF2-DC99-522B-8D64-AEDAEDAA70F5&utm_source=rss&utm_medium=rss
---

The LearnPress plugin for WordPress, in versions up to and including 4.4.10, contains a critical PHP Object Injection vulnerability (CVE-2026-104736). An unauthenticated attacker can exploit this vulnerability by submitting a maliciously crafted serialized object via the 'checkout-email' parameter during the checkout AJAX action. 

The application processes this input using sanitize_text_field(), which fails to strip serialized object syntax. The payload is subsequently saved to the LearnPress session table. During later requests, the LP_Session_Handler::get() method retrieves this data and passes it to LP_Helper::maybe_unserialize(), which invokes the PHP unserialize() function without any class-based restrictions. This lack of sanitization allows an attacker to control the deserialization process, potentially leading to remote code execution (RCE) or other unintended application states depending on the available gadget chains within the environment.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary code or manipulate application objects, posing a severe risk to the integrity and confidentiality of WordPress sites utilizing the LearnPress plugin. The CVSS base score of 9.8 indicates the high severity of this vulnerability, which affects all sites running vulnerable versions of the plugin.

## Recommendation

Prioritized actions for detection and remediation:

- Upgrade the LearnPress plugin to a version patched against CVE-2026-104736 immediately.
- Monitor webserver logs for suspicious POST requests containing serialized PHP object structures in the 'checkout-email' parameter.
- Audit the WordPress database for the LearnPress session table to identify any anomalous, persistent serialized object entries injected by unauthenticated sources.
