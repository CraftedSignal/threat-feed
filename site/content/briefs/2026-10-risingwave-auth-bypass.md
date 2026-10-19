---
title: Missing Authorization Vulnerability in RisingWave
slug: 2026-10-risingwave-auth-bypass
description: RisingWave versions before 3.1.0 contain a missing authorization vulnerability allowing low-privileged SQL users to perform arbitrary filesystem read and write operations.
date: "2026-10-19T16:08:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:risingwave:risingwave:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - database-security
vendors:
  - RisingWave
products:
  - RisingWave (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers holding schema CREATE privilege can set posix_fs.root or fs.path to any directory to read credentials and keys or write files as root.
    confidence_band: high
cves:
  - id: CVE-2026-112262
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112262
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Database Administration
  immediate_actions:
    - action: Upgrade RisingWave to version 3.1.0 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediation requires updating to version 3.1.0
  mitigation_plan:
    - priority: immediate
      action: Restrict CREATE privilege on schemas to trusted users
      owner: Database Administration
      addresses: CVE-2026-112262
      evidence: Attackers holding schema CREATE privilege can exploit the vulnerability
---

RisingWave versions prior to 3.1.0 are affected by a missing authorization vulnerability, tracked as CVE-2026-112262. The flaw resides in the handling of filesystem-based data sources and sinks, specifically `posix_fs` sources and `fs` sinks. An attacker possessing the `CREATE` privilege on a schema can manipulate the `posix_fs.root` or `fs.path` parameters to point to arbitrary directories on the underlying host filesystem. By exploiting this, a low-privileged SQL user can bypass intended access controls to read sensitive files, such as credentials and private keys, or perform arbitrary write operations. Given that the RisingWave service may operate with elevated privileges, this vulnerability enables the execution of unauthorized filesystem modifications, potentially resulting in full system compromise.

## Impact

Successful exploitation allows low-privileged SQL users to gain unauthorized access to any file accessible by the RisingWave process. In configurations where the service runs with root privileges, this results in immediate system-level compromise. The vulnerability is particularly dangerous for multi-tenant environments or instances where untrusted users are granted schema creation rights, as it allows for credential exfiltration and unauthorized file manipulation.

## Recommendation

1. Upgrade RisingWave to version 3.1.0 or later immediately to remediate CVE-2026-112262.
2. Audit database user permissions to restrict `CREATE` privileges on schemas to trusted users only.
3. Enforce strict filesystem-level permissions for the service account running RisingWave to limit the impact of potential arbitrary file read or write operations.
