---
brief_id: brief-2026-11-11-adminneo-sqlite-deletion-ghsa-6vfx-w7q3-42gq
event_id: brief-2026-11-11-adminneo-sqlite-deletion-ghsa-6vfx-w7q3-42gq
revision: 1
activity_at: "2026-11-11T11:52:56Z"
title: 'AdminNeo: SQLite database-list arbitrary file deletion (CVE-2026-96633)'
slug: 2026-11-adminneo-sqlite-deletion-ghsa-6vfx-w7q3-42gq
description: AdminNeo versions prior to 5.5.1 allow an authenticated user to perform arbitrary file deletion on the web server by exploiting an improper input validation flaw in the SQLite database drop operation.
date: "2026-11-11T11:52:56Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:adminneo:adminneo:*:*:*:*:*:*:*:*
vendors:
  - AdminNeo
products:
  - adminneo (< 5.5.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
    evidence: An authenticated AdminNeo SQLite user with a valid CSRF token can submit an arbitrary relative file path in the database-list db[] field, which AdminNeo unlinks even when the file is not a SQLite database.
    confidence_band: high
cves:
  - id: CVE-2026-96633
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-6vfx-w7q3-42gq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96633
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch AdminNeo to version 5.5.1 or later on all accessible web servers.
      owner: IT Operations
      due: 48h
      evidence: 'Vulnerable: < 5.5.1'
  hunt_leads:
    - lead: Monitor web server access logs for POST requests to the AdminNeo endpoint containing unexpected file paths or absolute paths in the db[] parameter.
      technique_id: T1485
      data_needed:
        - Webserver access logs (POST body parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The drop path passes submitted db[] values directly to unlink().
  mitigation_plan:
    - priority: immediate
      action: Upgrade adminneo to 5.5.1
      owner: IT Operations
      addresses: CVE-2026-96633
      evidence: Fixed in 5.5.1
---

AdminNeo contains an arbitrary file deletion vulnerability (CVE-2026-96633) within its SQLite driver. The application's `drop_databases()` function incorrectly trusts the `db[]` parameter provided in POST requests, passing it directly to the PHP `unlink()` function without validating that the targeted path corresponds to a legitimate SQLite database file or enforcing extension restrictions. An authenticated attacker can leverage this to delete any file on the filesystem that the web server process has sufficient permissions to remove.

## Attack Chain

1. Attacker authenticates to the AdminNeo web interface.
2. Attacker retrieves a valid CSRF token from the application session.
3. Attacker identifies a target file on the server filesystem that is writable by the web server process.
4. Attacker initiates a database drop request via the AdminNeo UI or a crafted POST request.
5. Attacker injects the arbitrary file path into the `db[]` parameter of the POST request.
6. The `drop_databases()` function receives the malicious path and proceeds to call `unlink()` on the file.
7. The target file is successfully deleted from the server.

## Impact

Successful exploitation allows for the deletion of arbitrary files accessible to the PHP process. This can lead to denial-of-service by deleting critical configuration or system files, or potentially disrupt other applications hosted on the same server.

## Recommendation

- Upgrade the AdminNeo package to version 5.5.1 or later immediately.
- Implement access control checks to ensure users can only drop databases that are explicitly listed as authorized for their session.
- Apply strict path validation and canonicalization to the `db[]` input parameter to prevent directory traversal and deletion of non-database files.
- Ensure the database deletion logic enforces file extension verification (e.g., `.db`, `.sdb`, `.sqlite`) equivalent to the validation logic used in database creation operations.
