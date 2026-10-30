---
brief_id: brief-2026-10-30-camel-azure-files-path-traversal
event_id: brief-2026-10-30-camel-azure-files-path-traversal
revision: 1
activity_at: "2026-10-30T16:52:14Z"
title: 'Apache Camel: Path traversal in camel-azure-files (CVE-2026-79986)'
slug: 2026-10-camel-azure-files-path-traversal
description: The camel-azure-files component in Apache Camel is vulnerable to path traversal (CVE-2026-79986) due to insufficient validation of filenames returned during Azure File share listing, allowing unauthorized file access, deletion, or renaming.
date: "2026-10-30T16:52:14Z"
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
  validation_status: Source verified against Apache Camel security advisory.
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - camel-azure-files
  - path-traversal
  - cve-2026-79986
  - apache
vendors:
  - Apache
products:
  - camel-azure-files (>= 4.0.0 < 4.18.5, >= 4.19.0 < 4.22.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Path traversal in camel-azure-files allows retrieval or deletion of files outside the directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: A listing name that is not a single path segment therefore resolved outside the polled directory for retrieval and, with delete/move/preMove/moveFailed/readLock=rename, deletion or rename.
    confidence_band: high
cves:
  - id: CVE-2026-79986
    cvss: 7.4
    epss: 0.00645
    kev_status: "false"
references:
  - https://camel.apache.org/security/CVE-2026-79986.html
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-79986
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-79986&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade camel-azure-files to 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Apache Camel security advisory fixes
  hunt_leads:
    - lead: Monitor application logs for unexpected file access patterns or error messages indicating traversal attempts (e.g., path resolution issues) within Camel Azure File consumers.
      technique_id: T1190
      data_needed:
        - Application logs (Camel consumer activity)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The azure-files consumer now applies the same containment check... a resolved path that falls outside the polled directory is skipped with a warning
  mitigation_plan:
    - priority: immediate
      action: Constrain consumer with filter/antInclude/include and disable delete/move operations
      owner: IT Operations
      addresses: CVE-2026-79986
      evidence: Mitigation if you cannot upgrade documentation in advisory
---

CVE-2026-79986 identifies a path traversal vulnerability in the `camel-azure-files` component of Apache Camel. The vulnerability arises because the consumer builds remote paths by concatenating a configured directory with file names reported in an Azure File share listing without verifying if the result stays within the intended directory. While the Azure Files REST service does not typically return path segments that include traversal sequences, the exposure enables unauthorized file operations if the storage backend is untrusted or compromised.

## Impact

Successful exploitation allows an attacker to perform file retrieval, deletion, or renaming of files outside the designated polled directory using the credentials assigned to the endpoint.

## Recommendation

- Upgrade affected Camel installations to the fixed versions: 4.18.5, 4.22.1, or 4.23.0.
- For environments where immediate upgrading is not possible, constrain the `camel-azure-files` consumer using `filter`, `antInclude`, or `include` to restrict file processing to single-segment names.
- Disable high-risk consumer options including `delete`, `move`, `preMove`, `moveFailed`, and `readLock=rename` when interacting with Azure File shares that are not fully trusted.
