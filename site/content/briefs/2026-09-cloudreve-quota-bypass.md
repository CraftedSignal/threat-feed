---
title: Cloudreve Storage Quota Bypass via TOCTOU Race Condition
slug: 2026-09-cloudreve-quota-bypass
description: Cloudreve v4 contains a Time-of-Check to Time-of-Use (TOCTOU) vulnerability that allows authenticated users to bypass storage quotas and exhaust host disk space by triggering concurrent, non-atomic upload session reservations.
date: "2026-09-23T01:54:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cloudreve:cloudreve:*:*:*:*:*:*:*:*
vendors:
  - Cloudreve
products:
  - Cloudreve (v4 < 4.0.0-20260715025621-7329602751c0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The same primitive is trivially amplifiable into a storage-based denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-77633
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-xj3h-wwxq-gfcj
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Cloudreve to version 4.0.0-20260715025621-7329602751c0 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version for remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 4.0.0-20260715025621-7329602751c0
      owner: IT Operations
      addresses: CVE-2026-77633
      evidence: Source advisory
---

Cloudreve v4 is vulnerable to a TOCTOU race condition within its `PrepareUpload` function, which governs how user storage quotas are enforced. The application fails to perform atomic quota checks and balance updates, separating the process into two distinct stages: a check (reading the current `used` byte count from the database) and a charge (incrementing the `users.storage` field). 

Because these operations are not enclosed within a database-level transaction lock (e.g., `SELECT ... FOR UPDATE`), multiple concurrent upload requests can read the same stale storage snapshot. This enables attackers to bypass `MaxStorage` limits defined by their user group. By sending multiple simultaneous requests, an attacker can reserve storage far exceeding their actual quota. This primitive is trivially escalated to a storage-based denial of service, where the reserved storage eventually materializes as actual file data written to disk, potentially exhausting the host's physical free space and disrupting service for all users. This vulnerability impacts all default deployments of Cloudreve v4 prior to version 4.0.0-20260715025621-7329602751c0.

## Attack Chain

1. Attacker authenticates to the Cloudreve instance using a standard user account with `Files.Write` permissions.
2. Attacker initiates multiple concurrent upload sessions (e.g., via script) targeting the `PrepareUpload` endpoint.
3. The `DBFS.validateUserCapacity` function for each request fetches the `used` storage value from the database snapshot simultaneously.
4. Each request process performs a validation check against the user's `MaxStorage` limit using the same stale usage value, all passing simultaneously.
5. Each request proceeds to the `inventory.CommitWithStorageDiff` stage, where the total requested size is added to the user's `storage` column in the database.
6. The sum of all concurrent reservations exceeds the configured `MaxStorage` quota.
7. Attacker completes the chunked uploads for all sessions, writing excess data to the physical disk.
8. Host disk space is exhausted, causing a denial of service for all users on the instance.

## Impact

Successful exploitation allows any authenticated user to ignore storage limitations, leading to unauthorized resource consumption and potential denial of service. By filling the host server's storage partition, an attacker can prevent all users from uploading files or accessing services, causing total availability loss for the Cloudreve instance.

## Recommendation

Prioritized actions for administrators:
- Upgrade Cloudreve to version 4.0.0-20260715025621-7329602751c0 or later to patch CVE-2026-77633.
- Monitor logs for unusual spikes in rapid, concurrent `PrepareUpload` requests originating from a single user session.
- Implement external storage monitoring to alert on rapid decreases in host filesystem availability, which may indicate storage-based DoS exploitation.
