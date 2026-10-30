---
brief_id: brief-2026-10-30-wordpress-plugin-priv-esc
event_id: brief-2026-10-30-wordpress-plugin-priv-esc
revision: 1
activity_at: "2026-10-30T07:20:18Z"
title: 'Export and Import Users and Customers: Privilege escalation in CSV import (CVE-2026-104368)'
slug: 2026-10-wordpress-plugin-priv-esc
description: A CSV parsing vulnerability in the WordPress Export and Import Users and Customers plugin (<= 2.7.5) allows authenticated attackers to escalate privileges to Administrator by injecting malicious records into exported user files.
date: "2026-10-30T07:20:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:export_and_import_users_and_customers_project:export_and_import_users_and_customers:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Export and Import Users and Customers (<= 2.7.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Subscriber-level access and above to escalate their privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-104368
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104368
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify new Administrator accounts created via the Export and Import Users and Customers plugin functionality
      technique_id: T1068
      data_needed:
        - WordPress user creation logs
        - Plugin activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The injected second row is then processed by hf_create_customer() as a new user record whose user_login, user_pass, user_email, and role are entirely attacker-controlled.
  mitigation_plan:
    - priority: immediate
      action: Update Export and Import Users and Customers plugin to the latest version (patch for CVE-2026-104368)
      owner: IT Operations
      addresses: CVE-2026-104368
      evidence: The Export and Import Users and Customers plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.7.5
---

The Export and Import Users and Customers plugin for WordPress contains a privilege escalation vulnerability (CVE-2026-104368) due to inconsistent CSV escape character handling. The exporter uses a backslash as the escape character, while the importer expects a double-quote. An attacker with Subscriber permissions can manipulate their Biographical Info field to inject a crafted CSV row that is interpreted as a new user creation during the import process.

## Attack Chain
1. Attacker authenticates to the WordPress site with Subscriber-level access.
2. Attacker updates their "Biographical Info" profile field with a crafted payload containing a backslash-quote sequence and a newline.
3. An administrator performs a bulk export of users using the Export and Import Users and Customers plugin.
4. The plugin exporter writes the attacker-controlled field to a CSV file, escaping it with a backslash.
5. The administrator imports the modified CSV file back into the WordPress instance.
6. The plugin importer parses the CSV using double-quote as an escape character, causing the injected newline to split the payload into a separate user record.
7. The `hf_create_customer()` function processes the injected second row as a new user.
8. A new Administrator account is created with credentials specified in the payload.

## Impact
An authenticated attacker can escalate their privileges to Administrator, gaining full control over the WordPress instance.

## Recommendation
- Update the Export and Import Users and Customers plugin to a version beyond 2.7.5 immediately.
- Audit existing user accounts for suspicious Administrator profiles created by non-administrative users.
- Restrict access to plugin export and import functionality to authorized administrators only.
