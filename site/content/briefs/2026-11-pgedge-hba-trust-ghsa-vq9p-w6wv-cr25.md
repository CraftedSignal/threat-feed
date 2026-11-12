---
brief_id: brief-2026-11-12-pgedge-hba-trust-ghsa-vq9p-w6wv-cr25
event_id: brief-2026-11-12-pgedge-hba-trust-ghsa-vq9p-w6wv-cr25
revision: 1
activity_at: "2026-11-12T22:16:54Z"
title: 'pgEdge Control Plane: Improper pg_hba.conf configuration (CVE-2026-125323)'
slug: 2026-11-pgedge-hba-trust-ghsa-vq9p-w6wv-cr25
description: The pgEdge Control Plane forces 'trust' authentication for all local and loopback connections in generated pg_hba.conf files, allowing local users to escalate privileges to Postgres superuser.
date: "2026-11-12T22:16:54Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:pgedge:control_plane:*:*:*:*:*:*:*:*
vendors:
  - pgEdge
products:
  - pgEdge Control Plane (<= 0.10.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any operating-system account that can reach the Postgres socket or the loopback interface on a database host can authenticate as any Postgres role, including the superuser, without presenting a credential.
    confidence_band: high
cves:
  - id: CVE-2026-125323
    cvss: 7.8
    epss: 0.00121
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-vq9p-w6wv-cr25
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade pgEdge Control Plane to v0.11.0 or later on all database nodes.
      owner: IT Operations
      due: 48h
      evidence: Patches are fixed in v0.11.0.
  hunt_leads:
    - lead: Audit pg_hba.conf files on all database hosts to identify the presence of 'trust' entries for local or loopback (127.0.0.1/::1) connections.
      data_needed:
        - File system access to /etc/pgEdge/pg_hba.conf or equivalent postgresql data directory location.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An operator who verifies their own deployment can confirm the issue by inspecting the generated pg_hba.conf on a database node for the entries above.
  mitigation_plan:
    - priority: immediate
      action: Set unix_socket_permissions to 0700 in postgresql.conf.
      owner: IT Operations
      addresses: CVE-2026-125323
      evidence: 'The only partial mitigation available is to restrict the Unix socket: set unix_socket_permissions to 0700.'
---

The pgEdge Control Plane automatically generates `pg_hba.conf` files that contain hard-coded `trust` authentication entries for Unix-socket and loopback connections. Because these entries are placed at the top of the configuration file, they take precedence over any operator-defined security rules. This enables any local operating-system account with access to the database host or Postgres socket to authenticate as any database role, including the superuser, without providing credentials. This issue is identified as CVE-2026-125323.

## Impact

Successful exploitation results in full control over all databases hosted on the affected instance, including the ability to read, modify, or destroy all data. On deployments using systemd, any local user can perform these actions. In containerized environments, the impact is limited to users who have already gained code execution within the container.

## Recommendation

- Upgrade pgEdge Control Plane to version v0.11.0 or later immediately. This update removes the hard-coded `trust` entries.
- For operators unable to upgrade, restrict file system permissions on the Unix socket for the database (e.g., set `unix_socket_permissions` to `0700`) to prevent unauthorized local accounts from accessing the socket path.
