---
brief_id: brief-2026-10-25-concrete-cms-idor
event_id: brief-2026-10-25-concrete-cms-idor
revision: 1
activity_at: "2026-10-25T05:40:43Z"
title: 'Concrete CMS: Insecure Direct Object Reference (CVE-2026-8237)'
slug: 2026-10-concrete-cms-idor
description: Concrete CMS versions 9.5.0 and earlier contain an IDOR vulnerability in the message_detail endpoint that allows unauthenticated attackers to retrieve private conversation messages and file attachment URLs by manipulating the messageId parameter.
date: "2026-10-25T05:40:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Pending production validation of frequency thresholds
cpes:
  - cpe:2.3:a:concretecms:concrete_cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - idor
  - information-disclosure
vendors:
  - Concretecms
products:
  - Concrete CMS (< 9.5.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The flaw exists in the /ccm/frontend/conversations/message_detail endpoint, which returns the full contents of conversation messages based solely on a user-supplied message identifier.
    confidence_band: high
cves:
  - id: CVE-2026-8237
    cvss: 5.3
    epss: 0.00743
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AJ2108-CVE-2026-8237
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AJ2108-CVE-2026-8237&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential CVE-2026-8237 IDOR Exploitation
    description: Detects potential exploitation attempts by monitoring the message_detail endpoint for high-frequency requests from a single IP, indicative of IDOR enumeration.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Concrete CMS to version 9.5.1
      owner: IT Operations
      due: 48h
      evidence: The issue is fixed in Concrete CMS 9.5.1.
  hunt_leads:
    - lead: Identify anomalous enumeration patterns for message_detail
      technique_id: T1592
      data_needed:
        - Web server logs containing requested URI and client IP
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker can enumerate message IDs and retrieve conversation content
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 9.5.1
      owner: IT Operations
      addresses: CVE-2026-8237
      evidence: The issue is fixed in Concrete CMS 9.5.1.
---

Concrete CMS versions 9.5.0 and earlier are vulnerable to an Insecure Direct Object Reference (IDOR) flaw (CVE-2026-8237). The vulnerability exists within the '/ccm/frontend/conversations/message_detail' endpoint, which fails to perform authorization checks when retrieving conversation messages based on a user-supplied 'messageId'. An attacker can enumerate valid message IDs to access private content and file attachments. The vulnerability is resolved in Concrete CMS version 9.5.1.

## Attack Chain

1. Attacker identifies a target instance of Concrete CMS running an affected version.
2. Attacker interacts with the '/ccm/frontend/conversations/message_detail' endpoint.
3. Attacker discovers the 'messageId' parameter via legitimate observation or enumeration.
4. Attacker modifies the 'messageId' parameter value in an HTTP GET request.
5. The application fetches the corresponding message object without verifying requester authorization.
6. The application returns the private message content and associated attachment download URLs to the unauthorized attacker.

## Impact

Successful exploitation results in the unauthorized disclosure of private conversation content and sensitive file attachment URLs from restricted or members-only forum areas.

## Recommendation

- Upgrade all instances of Concrete CMS to version 9.5.1 or later to implement required authorization checks for conversation messages.
- Review web server access logs for anomalous, high-frequency requests to the '/ccm/frontend/conversations/message_detail' endpoint originating from unauthenticated sessions.
