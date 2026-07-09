---
title: YesWiki PHP Object Injection Vulnerability (CVE-2026-52777)
slug: 2026-07-yeswiki-php-object-injection
description: An authenticated PHP Object Injection vulnerability (CVE-2026-52777) in YesWiki's `BazarImportAction`, specifically within the `unserialize` function, allows remote code execution (RCE) on the YesWiki server when an authenticated administrator's browser is targeted via a cross-site request forgery (CSRF) attack.
date: "2026-07-09T21:08:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - php
  - object-injection
  - web-application
  - csrf
vendors:
  - YesWiki
products:
  - composer/yeswiki/yeswiki
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Deliver an HTML page (email, chat, link) that auto-POSTs `importfiche[0]=<base64-encoded PHPGGC payload>` to `https://<wiki>/?BazaR&vue=importer&id_typeannonce=1`.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: These chains terminate in either `system($cmd)` (RCE1) or `file_put_contents($php_file, $contents)` (FW1) entry-points -- both sufficient to give the attacker shell on the YesWiki host.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The attacker can write web shells, exfiltrate other sites on shared hosting, modify `wakka.config.php`, dump the MySQL database, and pivot from there.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The attacker can write web shells, exfiltrate other sites on shared hosting, modify `wakka.config.php`, dump the MySQL database, and pivot from there.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9369-69wj-7m2f
rules:
  - title: Detect CVE-2026-52777 YesWiki PHP Object Injection Attempt
    description: Detects exploitation attempts for CVE-2026-52777, an authenticated PHP Object Injection vulnerability in YesWiki. Looks for POST requests to the Bazar importer endpoint containing 'importfiche' parameter with base64-encoded serialized object data.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1566.002
    data_sources:
      - webserver
rules_count: 1
---

A critical authenticated PHP Object Injection vulnerability, tracked as CVE-2026-52777, has been identified in YesWiki versions prior to 4.6.6. The flaw resides in the `BazarImportAction` component, specifically within the `unserialize` function in `tools/bazar/services/CSVManager.php`, which processes user-supplied data without proper class whitelisting. This oversight allows an attacker to instantiate arbitrary classes and trigger magic methods, facilitating gadget chains, such as those found in `doctrine/annotations` and `doctrine/cache` dependencies (e.g., PHPGGC chains `Doctrine/RCE1` or `Doctrine/FW1`), to achieve remote code execution. The vulnerability is made exploitable via a Cross-Site Request Forgery (CSRF) attack, as the affected action lacks CSRF protection, enabling a remote attacker to deliver a malicious HTML page that automatically triggers the payload when an authenticated administrator visits it. This allows an attacker to gain full control over the YesWiki hosting server.

## Attack Chain

1. The attacker identifies an authenticated administrator account on the target YesWiki instance.
2. The attacker crafts a malicious HTML page containing JavaScript that performs an auto-POST request to the vulnerable `bazarimport` endpoint (`/?BazaR&vue=importer&id_typeannonce=1`).
3. This POST request includes a `importfiche[0]` parameter containing a base64-encoded, serialized PHP object payload, leveraging a known gadget chain (e.g., from `doctrine/annotations` or `doctrine/cache`).
4. The malicious HTML page is delivered to the administrator via email, chat, or a link, and when the administrator opens the page, their browser automatically sends their session cookie along with the crafted POST request.
5. The YesWiki application processes the request; the `checkSecuredACL()` method passes because the request originates from an authenticated administrator session, and critically, no CSRF token check is performed.
6. The `importEntry` function in `tools/bazar/services/CSVManager.php` decodes the base64 string and `unserialize`s the PHP object without the `allowed_classes` restriction.
7. The deserialization process triggers the attacker-controlled gadget chain, leading to the execution of arbitrary PHP code (e.g., `system($cmd)`) or writing a web shell to the server.
8. The attacker gains remote code execution, obtaining an operating system shell on the YesWiki hosting server, bypassing the web application layer.

## Impact

Successful exploitation of CVE-2026-52777 results in immediate and complete remote code execution on the YesWiki server. This means an attacker who can trick an authenticated administrator into clicking a link can elevate their access from managing wiki content to having an operating system shell on the hosting box. The compromise allows attackers to write web shells for persistence, exfiltrate sensitive data including other websites on shared hosting environments, dump the entire MySQL database, modify critical configuration files such as `wakka.config.php`, and pivot to other systems within the network. This level of access grants full control over the server and its hosted data, posing a severe risk of data breach, service disruption, and further lateral movement.

## Recommendation

* **Patch CVE-2026-52777 immediately** by upgrading YesWiki to version 4.6.6 or newer. This addresses the vulnerability in `composer/yeswiki/yeswiki < 4.6.6`.
* **Deploy the provided Sigma rule** to your SIEM to detect exploitation attempts targeting the vulnerable `BazarImportAction` endpoint. Tune the rule for your environment.
* **Implement CSRF protection** for the `bazarimport` action to prevent cross-site request forgery attacks, specifically ensuring `CsrfTokenController::checkToken` is applied to the `'importentries'` mode in `tools/bazar/actions/BazarImportAction.php`.
* **Review `tools/bazar/services/CSVManager.php::importEntry`** to ensure `unserialize` calls either include `['allowed_classes' => false]` or, preferably, migrate to a safer JSON-based transport mechanism.
