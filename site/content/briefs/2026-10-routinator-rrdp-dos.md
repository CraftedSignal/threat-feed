---
brief_id: brief-2026-10-26-routinator-rrdp-dos
event_id: brief-2026-10-26-routinator-rrdp-dos
revision: 1
activity_at: "2026-10-26T19:45:24Z"
title: 'NLnet Labs Routinator: RRDP delta processing denial-of-service (CVE-2026-72753)'
slug: 2026-10-routinator-rrdp-dos
description: Routinator is vulnerable to a denial-of-service condition where specifically crafted or malformed RRDP notification files cause memory exhaustion during delta entry processing.
date: "2026-10-26T19:45:24Z"
lastmod: "2026-10-26T19:45:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: checked against NVD source; no concrete exploitation behavior provided for rule generation
cpes:
  - cpe:2.3:a:nlnetlabs:routinator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nlnet_labs:routinator:*:*:*:*:*:*:*:*
vendors:
  - NLnet Labs
products:
  - Routinator
cves:
  - id: CVE-2026-72753
    cvss: 8.2
    kev_status: "false"
  - id: CVE-2026-72754
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72753
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72754
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all instances of Routinator within the environment to facilitate patching upon vendor release.
      owner: IT Operations
      due: 48h
      evidence: Routinator is vulnerable to a potential denial-of-service condition
  hunt_leads:
    - lead: Identify abnormal memory growth in Routinator processes during RRDP repository synchronization.
      technique_id: T1499
      data_needed:
        - System memory usage telemetry (e.g., node_exporter, top, process monitoring)
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: If it encounters too many delta entries it may run out of memory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Routinator to the first version that addresses CVE-2026-72753 once available.
      owner: IT Operations
      addresses: CVE-2026-72753
      evidence: NLnet Labs Routinator vulnerability
updates:
  - at: "2026-10-26T19:45:32Z"
    level: L2
    summary: added CVE-2026-72754
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72754
---

CVE-2026-72753 describes a vulnerability in Routinator's RRDP notification file handling. When the software encounters an RRDP notification file containing gaps in delta entries, it improperly accepts and parses the file, resulting in potential data inconsistency. Furthermore, processing an excessive number of delta entries within a single file can lead to memory exhaustion, resulting in a denial-of-service condition.

## Impact

Successful exploitation allows for a denial-of-service condition via resource exhaustion (memory). Additionally, improper validation of delta gaps can result in the RPKI cache failing to synchronize correctly, leading to missing validation data.

## Recommendation

- Monitor the Routinator project release notes for an official patch addressing CVE-2026-72753.
- Inventory systems running Routinator and prepare for an upgrade cycle once the remediating version is released.
- Limit exposure of the Routinator RRDP synchronization process to trusted RPKI repositories where possible to mitigate the risk of processing malicious or malformed notification files.
