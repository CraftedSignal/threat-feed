---
brief_id: brief-2026-10-26-vmime-integer-underflow
event_id: brief-2026-10-26-vmime-integer-underflow
revision: 1
activity_at: "2026-10-26T23:47:30Z"
title: 'VMime: Stack-based buffer overflow in uuEncoder::decode (CVE-2026-116738)'
slug: 2026-10-vmime-integer-underflow
description: VMime version 0.9.2 and earlier contains an integer underflow vulnerability in the uuEncoder::decode function, allowing remote attackers to trigger a stack-based buffer overflow via crafted uuencoded MIME parts.
date: "2026-10-26T23:47:30Z"
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
cpes:
  - cpe:2.3:a:vmime:vmime:*:*:*:*:*:*:*:*
vendors:
  - VMime
products:
  - VMime (<= 0.9.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can send an email with a uuencoded line whose length character is b but is not a begin line, corrupting stack memory to crash the application or potentially execute code.
    confidence_band: high
cves:
  - id: CVE-2026-116738
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116738
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using VMime library version 0.9.2 or earlier.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects VMime through 0.9.2
  hunt_leads:
    - lead: Identify emails or MIME content containing uuencoded sections where the line starts with b but lacks the valid begin signature.
      technique_id: T1203
      data_needed:
        - Email gateway logs
        - MIME parsing application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can send an email with a uuencoded line whose length character is b but is not a begin line
  mitigation_plan:
    - priority: immediate
      action: Upgrade VMime library to a version containing the fix for CVE-2026-116738.
      owner: IT Operations
      addresses: CVE-2026-116738
      evidence: VMime through 0.9.2 contains an integer underflow
---

VMime library versions through 0.9.2 are susceptible to an integer underflow within the `uuEncoder::decode` function. This flaw is triggered when an application processes a crafted uuencoded MIME part where a line begins with the length character 'b' but does not constitute a valid 'begin' line. This input corruption leads to a stack-based buffer overflow, which can result in application denial of service or potential remote code execution.

## Impact
Successful exploitation allows remote attackers to corrupt stack memory. The primary observed impact is application instability, with a theoretical potential for arbitrary code execution depending on the host application implementation.

## Recommendation
- Inventory systems and applications that utilize the VMime library (up to 0.9.2).
- Prioritize upgrading the VMime library to a patched version once released by the maintainers.
- Implement email filtering or MIME-parsing pre-processors to inspect and discard malformed uuencoded MIME parts that match the length character 'b' logic identified as malicious.
