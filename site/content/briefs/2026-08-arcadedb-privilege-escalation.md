---
title: ArcadeDB Privilege Escalation via JavaScript Triggers
slug: 2026-08-arcadedb-privilege-escalation
description: ArcadeDB versions before 26.7.3 insecurely expose the LocalDatabase object to JavaScript triggers, allowing attackers with schema update permissions to perform unauthorized administrative actions.
date: "2026-08-02T13:35:54Z"
lastmod: "2026-08-02T13:36:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - privilege-escalation
  - database
vendors:
  - ArcadeData
products:
  - ArcadeDB
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with UPDATE_SCHEMA permission can create triggers that execute JavaScript to create server-wide admin users.
    confidence_band: high
cves:
  - id: CVE-2026-67356
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67356
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-38pf-6hp2-pxww
  - https://www.vulncheck.com/advisories/arcadedb-before-privilege-escalation-via-javascript-trigger
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67357
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-p9wc-4fhr-78wm
  - https://www.vulncheck.com/advisories/arcadedb-information-disclosure-via-get-server-settings
rules:
  - title: Detect ArcadeDB Cluster Token Impersonation Attempt
    description: Detects HTTP requests using X-ArcadeDB-Forwarded-User set to root, which indicates a potential impersonation attempt exploiting CVE-2026-67357.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-02T13:36:04Z"
    level: L2
    summary: 'added detection rule: Detect ArcadeDB Cluster Token Impersonation Attempt'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67357
---

ArcadeDB versions prior to 26.7.3 contain a security flaw where the `LocalDatabase` object is bound into JavaScript trigger contexts with `HostAccess.ALL`. This misconfiguration allows users with the `UPDATE_SCHEMA` permission to execute arbitrary JavaScript code that bypasses the security manager. Specifically, an authenticated attacker can invoke sensitive methods such as `getSecurity().createUser()` without appropriate authorization checks. By creating a malicious database trigger, a low-privileged user can escalate their privileges to become a server-wide administrator. This vulnerability (CVE-2026-67356) represents a significant risk for environments where database schema management is delegated to non-administrative users.

## Attack Chain

1. Attacker authenticates to the ArcadeDB instance with valid credentials possessing `UPDATE_SCHEMA` permissions.
2. Attacker interacts with the database management API or console to define a new JavaScript trigger.
3. The trigger is crafted to invoke the insecurely bound `LocalDatabase` object.
4. The JavaScript execution context uses `HostAccess.ALL`, providing the script unrestricted access to core internal objects.
5. The attacker's script calls `getSecurity().createUser()` to provision a new administrative user.
6. The application fails to enforce permission checks during the method invocation due to the exposed context.
7. A new account with administrative privileges is created.
8. Attacker authenticates with the newly created admin account to achieve full server compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain full administrative control over the ArcadeDB server. This can lead to complete data exfiltration, unauthorized modification or deletion of all databases, and persistent access to the underlying infrastructure. Organizations relying on ArcadeDB for critical data storage are at high risk if schema modification permissions are assigned to users who are not fully trusted.

## Recommendation

1. Upgrade ArcadeDB to version 26.7.3 or later immediately to restrict `HostAccess` bindings in JavaScript contexts.
2. Review current user role assignments and revoke `UPDATE_SCHEMA` permissions from any user accounts that do not require them.
3. Audit database triggers for suspicious JavaScript code that interacts with the `getSecurity()` or `createUser()` methods.
