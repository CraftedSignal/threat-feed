---
title: Craft Commerce SQL Injection Leading to Remote Code Execution
slug: 2024-01-craft-commerce-rce
description: A SQL injection vulnerability in the Craft Commerce TotalRevenue widget can lead to remote code execution through a chain of vulnerabilities including unsanitized widget settings in SQL expressions, enabled PDO Multi-Statement Queries, unrestricted unserialize(), and a FileCookieJar gadget chain, allowing attackers to write a PHP webshell to the server's webroot and achieve arbitrary command execution as the PHP process user.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - craft-commerce
  - sql-injection
  - rce
  - webshell
vendors:
  - Craft
products:
  - Craft Commerce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
cves:
  - id: CVE-2026-32271
references:
  - https://github.com/advisories/GHSA-875v-7m49-8x88
rules:
  - title: Craft Commerce Webshell Creation via FileCookieJar
    description: Detects the creation of a PHP webshell in the webroot via file_put_contents, potentially exploited through the FileCookieJar gadget chain in Craft Commerce RCE.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Craft Commerce Unauthorized Queue Run
    description: Detects GET requests to /actions/queue/run without prior authentication, indicating potential exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in Craft Commerce versions 4.0.0 through 4.10.2 and 5.0.0 through 5.5.4. This vulnerability allows any authenticated control panel user to achieve remote code execution (RCE) on the target server. The attack leverages a SQL injection flaw in the TotalRevenue widget, where unsanitized widget settings are directly interpolated into a SQL expression. The default configuration of PHP's PDO MySQL, which enables `CLIENT_MULTI_STATEMENTS`, is exploited to inject additional SQL statements. This allows the attacker to write a maliciously serialized PHP object into the queue table. The yii2-queue PhpSerializer then unserializes this object without restrictions, leading to instantiation of an attacker-controlled object. Finally, a gadget chain within the GuzzleHttp\Cookie\FileCookieJar dependency is used to write a PHP webshell to the server's webroot. This complex chain of vulnerabilities culminates in arbitrary command execution as the PHP process user. Queue processing is triggered via GET `/actions/queue/run`, an endpoint that requires no authentication.

## Attack Chain

1. An attacker authenticates to the Craft Commerce control panel as any user.
2. The attacker sends a POST request to `/admin/actions/dashboard/create-widget` to create a TotalRevenue widget.
3. The `settings[type]` parameter in the POST request contains a stacked SQL injection payload. This payload leverages `CLIENT_MULTI_STATEMENTS` to inject an INSERT statement after the initial SELECT query. The INSERT statement writes a serialized PHP object into the queue table.
4. The server returns an HTTP 500 error, indicating the INSERT statement was successfully committed.
5. The attacker triggers queue processing by sending a GET request to `/actions/queue/run`.
6. The queue consumer deserializes the injected PHP object from the queue table using `unserialize()`, without any allowed classes restrictions.
7. This deserialization triggers the `__destruct()` method of the `GuzzleHttp\Cookie\FileCookieJar` class, which contains an unguarded call to `file_put_contents()`. This writes a PHP webshell (e.g., `poc_rce.php`) to the webroot.
8. The attacker accesses the webshell via a GET request (e.g., `GET /poc_rce.php?c=id`), executing arbitrary commands as the PHP process user.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the Craft Commerce server as the PHP process user. This can lead to complete system compromise, including data theft, modification, or destruction. Given the nature of e-commerce platforms, this could result in significant financial loss, reputational damage, and legal repercussions. The fact that any authenticated control panel user can trigger this vulnerability significantly widens the attack surface. This vulnerability impacts all versions of Craft Commerce between 4.0.0 and 4.10.2 and between 5.0.0 and 5.5.4.

## Recommendation

*   Immediately upgrade Craft Commerce to a patched version (4.10.3+ or 5.5.5+) to remediate CVE-2026-32271.
*   Deploy the Sigma rule "Craft Commerce Webshell Creation via FileCookieJar" to detect webshell creation attempts via `file_put_contents`.
*   Monitor web server logs for requests to `/actions/queue/run` to detect unauthorized queue processing, referencing the attack chain description.
*   Consider disabling `CLIENT_MULTI_STATEMENTS` in your PHP PDO configuration if possible, but be aware of potential compatibility issues.
