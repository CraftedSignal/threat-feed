---
brief_id: brief-2026-11-09-floci-path-traversal
event_id: brief-2026-11-09-floci-path-traversal
revision: 1
activity_at: "2026-11-09T03:24:02Z"
title: 'floci-io Floci: S3 Destination configuration path traversal (CVE-2026-124509)'
slug: 2026-11-floci-path-traversal
description: A path traversal vulnerability in the S3Destination.bucketName function of floci-io Floci allows remote attackers to manipulate the BucketARN argument via the S3 Destination Configuration Handler.
date: "2026-11-09T03:24:02Z"
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
  validation_status: Source verified; environment validation pending upgrade.
cpes:
  - cpe:2.3:a:floci-io:floci:*:*:*:*:*:*:*:*
vendors:
  - floci-io
products:
  - Floci (<= 2.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-124509
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124509
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Floci to version 2.2.0
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 2.2.0 is sufficient to fix this issue.
  hunt_leads:
    - lead: Identify abnormal path traversal characters (../) in S3 BucketARN configuration parameters
      technique_id: T1190
      data_needed:
        - Application logs for S3 Destination Configuration updates
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Such manipulation of the argument BucketARN leads to path traversal.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.2.0
      owner: IT Operations
      addresses: CVE-2026-124509
      evidence: Upgrading to version 2.2.0 is sufficient to fix this issue.
---

floci-io Floci versions up to 2.1.0 are vulnerable to a path traversal attack within the S3 Destination Configuration Handler. The issue exists in the function S3Destination.bucketName located in 'services/firehose/model/DeliveryStreamDescription.java'. Attackers can exploit this remotely by providing malicious input to the BucketARN argument. A patch is available in commit b986b95074ef524019be7af51e1df172e48faa4b, and the vendor has released version 2.2.0 to resolve the vulnerability. Public exploit code is available.

## Impact
Successful exploitation allows for path traversal, which may lead to unauthorized access to files or sensitive data within the environment hosting the Floci service.

## Recommendation
- Upgrade all instances of floci-io Floci to version 2.2.0 or later immediately.
- Audit logs for the S3 Destination Configuration Handler to identify anomalous inputs to the BucketARN parameter.
