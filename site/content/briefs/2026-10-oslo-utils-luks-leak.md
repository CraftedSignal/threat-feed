---
brief_id: brief-2026-10-22-oslo-utils-luks-leak
event_id: brief-2026-10-22-oslo-utils-luks-leak
revision: 1
activity_at: "2026-10-22T19:57:20Z"
title: 'OpenStack oslo.utils: Information exposure of LUKS key material'
slug: 2026-10-oslo-utils-luks-leak
description: The oslo.utils library contains an information exposure vulnerability in its LUKS inspector that can result in sensitive cryptographic key material being written to system logs when processing LUKSv1 disk images.
date: "2026-10-22T19:57:20Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
tags:
  - openstack
  - information-exposure
  - log-security
vendors:
  - OpenStack
products:
  - oslo.utils
references:
  - https://seclists.org/oss-sec/2026/q4/311
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to log aggregation environments that ingest OpenStack component logs
      owner: SOC
      due: 24h
      evidence: Exposure of cryptographic key material in logs
  enrichment_needed:
    - item: Patch release information for oslo.utils
      owner: CTI
      reason: Determine the safe version to upgrade to once available
      evidence: Source advisory indicates a vulnerability exists
  mitigation_plan:
    - priority: immediate
      action: Disable non-essential logging for OpenStack utility components until a patch is applied
      owner: IT Operations
      addresses: oslo.utils LUKS inspection log leak
      evidence: Source notes potential key material exposure in logs
---

The oslo.utils library, a common utility component in OpenStack, contains a security flaw in its LUKS inspector functionality. When the library processes a LUKSv1 image protected by a passphrase, it may inadvertently log the cryptographic key material to system logs. This exposure provides sufficient data for an unauthorized actor with access to log files to decrypt the affected disk images.

## Impact
The primary impact is the unauthorized exposure of disk encryption keys in system logs. This allows for potential full data decryption of LUKSv1 volumes if logs are intercepted or improperly secured.

## Recommendation
- Audit system and application log repositories for the presence of cryptographic material or unexpected debugging output from oslo.utils.
- Review OpenStack or service-specific security advisories for patches addressing this library.
- Apply restricted access controls to log aggregation platforms to prevent unauthorized access to potentially sensitive log entries.
