---
title: Race Condition Vulnerability in FileCodeBox
slug: 2026-08-filecodebox-race-condition
description: A race condition vulnerability in the update_file_usage function of FileCodeBox versions up to 2.3 allows remote attackers to manipulate file usage limits.
date: "2026-08-30T15:10:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:vastsa:filecodebox:*:*:*:*:*:*:*:*
vendors:
  - vastsa
products:
  - FileCodeBox (< 2.5.0)
cves:
  - id: CVE-2026-82543
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82543
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FileCodeBox to version 2.5.0
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 2.5.0 is able to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to FileCodeBox 2.5.0
      owner: IT Operations
      addresses: CVE-2026-82543
      evidence: Upgrading to version 2.5.0 is able to resolve this issue.
---

A race condition vulnerability exists in the Pickup Limit Handler component of vastsa FileCodeBox, specifically within the update_file_usage function found in apps/base/views.py. This flaw, tracked as CVE-2026-82543, affects all versions up to and including 2.3. The vulnerability can be exploited remotely by an unauthenticated attacker to manipulate file usage constraints, potentially bypassing intended limits on file access or storage. Public exploit code is currently available, increasing the risk of exploitation by threat actors. Defenders should prioritize patching, as this vulnerability represents a significant security oversight in the handling of concurrent file operations. The maintainers have released version 2.5.0 to address this issue, which includes the necessary logic fixes in the affected code path.

## Impact

Successful exploitation of CVE-2026-82543 allows remote attackers to bypass resource limits managed by the Pickup Limit Handler. This may lead to unauthorized data retrieval or denial of service through resource exhaustion. While the scope of target environments is primarily installations of FileCodeBox, the availability of public exploit code increases the likelihood of opportunistic attacks against exposed instances.

## Recommendation

- Upgrade FileCodeBox to version 2.5.0 immediately to remediate CVE-2026-82543.
- Apply the patch identified by commit hash 8d7d856c62d73badd0797eb4daec8d2ff10a403a if upgrading the full application is not immediately feasible.
- Review web server access logs for anomalous request patterns targeting /apps/base/views.py or endpoints associated with the Pickup Limit Handler that exhibit high-frequency requests characteristic of race condition exploitation.
