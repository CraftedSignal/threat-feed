---
title: Hard-Coded Credentials Vulnerability in Rapyd Admin
slug: 2026-10-rapyd-admin-hardcoded-creds
description: Rapyd Admin versions 9.0.0 through 9.19.x contain a hard-coded credential vulnerability that allows remote unauthenticated attackers to gain global super-admin access.
date: "2026-10-12T22:39:10Z"
lastmod: "2026-10-12T22:42:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rapyd:rapyd_admin:9.0.0:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - rapyd
  - cve-2026-109567
vendors:
  - Rapyd
products:
  - Rapyd Admin (9.0.0 - 9.19.x)
  - Rapyd Admin (9.0.0-9.19.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Rapyd Admin from 9.0.0 before 9.20.0 contains a hard-coded credentials vulnerability that allows remote unauthenticated attackers to gain super-admin access through an AuthSeeder-created admin@laravel account with password admin.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The account is seeded by the setup installer and silently re-created on every rpd:make run, letting attackers log in as a global super admin.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Rapyd Admin from 9.0.0 before 9.20.0 contains an improper privilege management vulnerability in the UsersEdit Livewire component that allows users with the edit users permission to assign themselves the admin role.
    confidence_band: high
cves:
  - id: CVE-2026-109566
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109566
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109567
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Rapyd Admin to 9.20.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109566 disclosure recommends upgrading to version 9.20.0.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the 'admin@laravel' account if it exists in the user database.
      owner: IT Operations
      addresses: CVE-2026-109566
      evidence: Source documentation identifies 'admin@laravel' as the hard-coded administrative account.
updates:
  - at: "2026-10-12T22:42:45Z"
    level: L2
    summary: added coverage for Rapyd Admin (9.0.0-9.19.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109567
---

Rapyd Admin versions 9.0.0 through 9.19.x contain a critical hard-coded credential vulnerability (CVE-2026-109566). During the initial setup of the application, the `AuthSeeder` component automatically generates a default administrative account with the email 'admin@laravel' and the password 'admin'. This behavior is persistent, as the account is silently re-created or reset whenever the `rpd:make` command is executed on the server. Because this default account grants global super-admin privileges, remote unauthenticated attackers can use these credentials to gain full administrative control over the application. Successful exploitation results in complete bypass of tenant scoping and per-record authorization controls, potentially leading to unauthorized data access and total system compromise. This issue affects all deployments using the specified vulnerable versions, necessitating an immediate upgrade to version 9.20.0 or later.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.8, reflecting its high impact and ease of exploitability. Successful attacks result in full administrative access to the Rapyd Admin platform. This allows attackers to bypass organizational multi-tenancy and authorization boundaries, leading to full data exfiltration, administrative configuration changes, and potential further compromise of the underlying infrastructure. The number of impacted organizations is significant due to the prevalence of Rapyd Admin in web application deployments.

## Recommendation

- Upgrade Rapyd Admin to version 9.20.0 or later immediately to remove the `AuthSeeder` logic that generates the hard-coded credentials.
- Audit all administrative logs for successful logins using the 'admin@laravel' email address.
- If immediate patching is not possible, disable the `rpd:make` command execution and ensure that the administrative interface is not exposed to the public internet.
