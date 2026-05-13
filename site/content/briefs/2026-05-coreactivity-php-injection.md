---
title: 'coreActivity: Activity Logging for WordPress Plugin Vulnerable to PHP Object Injection (CVE-2026-7635)'
slug: 2026-05-coreactivity-php-injection
description: 'The coreActivity: Activity Logging for WordPress plugin for WordPress is vulnerable to PHP Object Injection (CVE-2026-7635), allowing unauthenticated attackers to inject a crafted PHP serialized payload via the User-Agent header, leading to a persistent Denial of Service condition.'
date: "2026-05-13T15:50:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - wordpress
  - php object injection
  - denial of service
vendors:
  - WordPress
products:
  - 'coreActivity: Activity Logging for WordPress plugin <= 3.0'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-7635
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7635
rules:
  - title: Detect CVE-2026-7635 Exploitation Attempt via Malicious User-Agent
    description: Detects CVE-2026-7635 exploitation attempt via User-Agent header containing PHP serialization syntax.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-7635 - WordPress Logmeta Table User-Agent PHP Object Injection
    description: Detects potential CVE-2026-7635 exploitation by identifying User-Agent strings containing PHP serialization syntax stored in the WordPress logmeta table.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - initial_access
    techniques:
      - T1499.004
    data_sources:
      - database
      - mysql
rules_count: 2
---

The coreActivity: Activity Logging for WordPress plugin, a WordPress plugin, is susceptible to a PHP Object Injection vulnerability (CVE-2026-7635) affecting all versions up to and including 3.0. This flaw arises because the plugin fails to properly validate or sanitize PHP serialization syntax present within the User-Agent HTTP header before persisting it to the logmeta table. Subsequently, the plugin invokes `maybe_unserialize()` on every retrieved `meta_value` in `query_metas()` without ensuring the data's original serialization by the application. This critical oversight enables unauthenticated attackers to inject malicious PHP serialized payloads via the User-Agent header during any logged event. This can occur during routine actions such as a failed login attempt. When an administrator accesses the Logs page, the injected payload undergoes deserialization and is passed to `DeviceDetector::setUserAgent()`, triggering a Fatal TypeError. This results in a persistent Denial of Service (DoS) condition, effectively preventing administrator access to the Logs page.

## Attack Chain

1. An unauthenticated attacker sends an HTTP request to the WordPress site.
2. The attacker crafts the User-Agent header to contain a malicious PHP serialized object.
3. The coreActivity plugin logs the HTTP request, including the tainted User-Agent string, storing it in the `logmeta` table.
4. An administrator attempts to view the activity logs via the WordPress admin panel.
5. The plugin's `query_metas()` function retrieves the stored User-Agent string from the database.
6. The `maybe_unserialize()` function is called on the retrieved User-Agent string, deserializing the attacker's payload.
7. The deserialized object is passed to the `DeviceDetector::setUserAgent()`, triggering a Fatal TypeError.
8. The Fatal TypeError prevents the administrator from accessing the Logs page, resulting in a persistent Denial-of-Service (DoS) condition.

## Impact

Successful exploitation of this vulnerability (CVE-2026-7635) results in a persistent Denial of Service (DoS) condition, preventing administrators from accessing the activity logs page. This could hinder security monitoring and incident response efforts, giving attackers more time to conduct malicious activities. The vulnerability impacts all WordPress sites using the coreActivity plugin versions 3.0 and below. A CVSS v3.1 base score of 8.1 reflects the high potential for disruption and impact.

## Recommendation

*   Upgrade the coreActivity: Activity Logging for WordPress plugin to a version greater than 3.0 to patch CVE-2026-7635.
*   Deploy the Sigma rule "Detect CVE-2026-7635 Exploitation Attempt via Malicious User-Agent" to detect attempts to inject malicious PHP serialized objects via the User-Agent header.
*   Review web server logs for suspicious User-Agent strings containing PHP serialization syntax to identify potential exploitation attempts.
