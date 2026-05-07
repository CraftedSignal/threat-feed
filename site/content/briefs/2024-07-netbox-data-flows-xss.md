---
title: netbox-data-flows Stored XSS Vulnerability in ObjectAlias Names
slug: 2024-07-netbox-data-flows-xss
description: The netbox-data-flows plugin is vulnerable to stored cross-site scripting (XSS). An authenticated user with permissions to create or edit ObjectAlias objects can inject arbitrary HTML/JavaScript into the alias name. This payload is then rendered unescaped in DataFlow table views, leading to XSS when another user views the affected page. Successful exploitation can result in session theft, privileged action execution, and data exfiltration.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - netbox
  - data-flows
  - stored-xss
vendors:
  - netbox
products:
  - netbox-data-flows (<= 1.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-v7qw-hx66-4w9x
rules:
  - title: Detect netbox-data-flows XSS Payload in ObjectAlias Name
    description: Detects attempts to create ObjectAlias objects with potential XSS payloads in the name field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect netbox-data-flows XSS Payload in ObjectAlias Edit
    description: Detects attempts to edit ObjectAlias objects and inject XSS payloads in the name field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The `netbox-data-flows` plugin for NetBox is susceptible to a stored cross-site scripting (XSS) vulnerability (<=1.5.0). An attacker with authenticated access to create or modify `ObjectAlias` objects can inject malicious HTML/JavaScript code into the `name` field of an alias. This injected code is then rendered without proper sanitization within the `DataFlow` table views. When another user, particularly one with elevated privileges, views a `DataFlow` that includes the malicious alias, the injected script executes within their browser session. This can lead to session hijacking, unauthorized actions performed on behalf of the victim user, and the potential exfiltration of sensitive data from the NetBox instance. This vulnerability impacts any page rendering `DataFlowTable`, including the main Data Flow list page and model tabs that reuse `DataFlowTable`.

## Attack Chain

1.  Attacker logs into NetBox with valid credentials and permissions to create/edit `ObjectAlias` objects.
2.  Attacker creates a new `ObjectAlias` object.
3.  Within the `name` field of the `ObjectAlias`, the attacker injects a malicious JavaScript payload such as `<img src=x onerror=alert(document.domain)>`.
4.  Attacker creates or edits a `DataFlow` object.
5.  The attacker associates the malicious `ObjectAlias` with either the `sources` or `destinations` field of the `DataFlow` object.
6.  The victim user logs into NetBox and navigates to the Data Flow list page or any page rendering the `DataFlowTable`.
7.  The `DataFlowTable` attempts to render the `sources` or `destinations` which contains the malicious `ObjectAlias`. The `object_list_to_string()` function in `netbox_data_flows/utils/helpers.py` generates HTML using the unescaped `ObjectAlias.name` field.
8.  The injected JavaScript within the `ObjectAlias.name` executes in the victim's browser, potentially leading to session theft or unauthorized actions.

## Impact

This stored XSS vulnerability in `netbox-data-flows` can affect any authenticated NetBox user who views a page rendering the affected `DataFlow` table. The impact is amplified when higher-privileged users are targeted. Successful exploitation allows an attacker to steal user sessions, perform privileged actions on behalf of the victim, and exfiltrate sensitive data accessible within NetBox. The vulnerability affects versions 1.5.0 and earlier of the `netbox-data-flows` plugin.

## Recommendation

*   Upgrade the `netbox-data-flows` plugin to a version greater than 1.5.0 to remediate the vulnerability (Affected Packages).
*   Deploy the Sigma rule "Detect netbox-data-flows XSS Payload in ObjectAlias Name" to detect attempts to create `ObjectAlias` objects with malicious payloads in the `name` field (rules).
*   Monitor NetBox logs for suspicious activity related to `ObjectAlias` creation and modification (logsource).
*   Review existing `ObjectAlias` objects for any potentially malicious code in the `name` field (ObjectAlias.name).
