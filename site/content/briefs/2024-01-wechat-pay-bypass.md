---
title: WeChat Pay Callback Signature Bypass via Host Header Manipulation
slug: 2024-01-wechat-pay-bypass
description: A vulnerability exists in yansongda/pay where signature verification is skipped when the Host header is `localhost`, allowing attackers to forge payment notifications.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wechatpay
  - signature-bypass
  - payment-fraud
  - webserver
vendors:
  - Yansongda
products:
  - yansongda/pay
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-q938-ghwv-8gvc
rules:
  - title: Detect WeChat Pay Callback with Localhost Host Header
    description: Detects WeChat Pay callback requests with a 'localhost' Host header, indicating a potential signature bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeChat Pay Callback with Invalid Signature
    description: This rule detects WeChat Pay callbacks where the signature cannot be verified. Requires access to the relevant public key for signature validation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `verify_wechat_sign()` function in versions 3.7.19 and earlier of the `yansongda/pay` package contains a vulnerability that allows attackers to bypass signature verification for WeChat Pay callbacks. Specifically, if the `Host` header of an incoming HTTP request to the callback endpoint is set to `localhost`, the function will skip the RSA signature check entirely. This is due to an unconditional check within the `verify_wechat_sign()` function in `src/Functions.php`. This vulnerability can be exploited to create fake payment success notifications, potentially leading to fraudulent transactions. The attack requires no authentication and can be performed purely over the network. While real-world exploitation might be limited by web application firewalls or reverse proxies filtering the Host header, the underlying vulnerability remains a risk.

## Attack Chain

1. Attacker identifies a vulnerable application using `yansongda/pay` for WeChat Pay integrations (version <= 3.7.19).
2. Attacker crafts a malicious HTTP POST request targeting the WeChat Pay callback endpoint (e.g., `/payment/wechat/callback`).
3. The crafted request includes the header `Host: localhost`.
4. The request also contains other required WeChat Pay headers like `Wechatpay-Serial`, `Wechatpay-Timestamp`, `Wechatpay-Nonce`, and `Wechatpay-Signature` but the `Wechatpay-Signature` value can be arbitrary.
5. The request body contains a JSON payload mimicking a successful transaction notification with a forged `id` and `event_type`.
6. The vulnerable `verify_wechat_sign()` function in `src/Functions.php` receives the request.
7. Due to the `Host: localhost` header, the signature verification step is skipped.
8. The application incorrectly processes the forged notification and marks the order as paid, resulting in the attacker receiving goods or services without payment.

## Impact

Successful exploitation of this vulnerability can lead to significant payment fraud, as attackers can receive goods or services without making actual payments. The attack requires no authentication and can be performed remotely. Affected applications are those utilizing the `yansongda/pay` package version 3.7.19 or earlier for WeChat Pay callback handling. The impact is primarily economic, with potential losses stemming from unfulfilled payments. While real-world exploitation may be mitigated by network-level controls, the vulnerability poses a risk to unpatched systems or misconfigured environments.

## Recommendation

*   Upgrade the `yansongda/pay` package to a version greater than 3.7.19 to remediate CVE-2026-33661.
*   Implement a web application firewall (WAF) rule to block or sanitize `Host` headers containing `localhost` on WeChat Pay callback endpoints, mitigating the vulnerability even in unpatched systems.
*   Deploy the Sigma rule `Detect WeChat Pay Callback with Localhost Host Header` to identify attempts to exploit this vulnerability.
*   Review and harden the configuration of your reverse proxy (e.g., Nginx, Apache) to ensure it properly validates and sanitizes incoming HTTP request headers, especially the `Host` header, preventing attackers from injecting malicious values.
