---
title: Concrete CMS IDOR Vulnerability in Conversation Rating Endpoint
slug: 2026-08-concrete-cms-idor
description: Concrete CMS versions prior to 9.5.1 contain an IDOR vulnerability in the get_rating endpoint that allows unauthenticated attackers to enumerate message IDs and disclose rating data for private content.
date: "2026-08-31T01:18:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:concretecms:concrete_cms:*:*:*:*:*:*:*:*
tags:
  - idor
  - information-disclosure
  - web-application
  - reconnaissance
vendors:
  - Concretecms
products:
  - Concrete Cms (< 9.5.1)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An unauthenticated attacker can supply arbitrary 'message_id' parameters to enumerate valid message identifiers.
    confidence_band: high
cves:
  - id: CVE-2026-8239
    cvss: 5.3
    epss: 0.00195
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AJ2108-CVE-2026-8239
rules:
  - title: Detect Potential IDOR Enumeration on Concrete CMS
    description: Detects suspicious patterns of access to the get_rating endpoint, suggesting enumeration of message IDs
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
    - action: Upgrade all Concrete CMS instances to 9.5.1
      owner: IT Operations
      due: 48h
      evidence: Vendor fix for CVE-2026-8239
  mitigation_plan:
    - priority: immediate
      action: Upgrade Concrete Cms to 9.5.1
      owner: IT Operations
      addresses: CVE-2026-8239
      evidence: Reported remediation version
---

Concrete CMS versions 9.5.0 and earlier are affected by an Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-8239. The vulnerability exists within the '/ccm/frontend/conversations/get_rating' endpoint. This endpoint accepts a 'message_id' parameter via a GET request and returns the rating score of the corresponding message. Crucially, the application fails to perform any authorization checks to verify if the requester has permission to access the requested message object.

By supplying sequential or arbitrary numeric identifiers in the 'message_id' parameter, an unauthenticated attacker can determine the existence of private messages and retrieve their associated rating scores. This information disclosure flaw allows for the enumeration of messages within the system. The issue is remediated in Concrete CMS version 9.5.1, which introduces authorization checks to ensure users can only access information for which they have explicit permissions.

## Impact

Successful exploitation allows unauthenticated attackers to conduct reconnaissance on system messaging activity. By iterating through message IDs, an attacker can confirm the existence of private conversations and extract rating data, leading to the exposure of information that should otherwise be restricted. While the impact is limited to metadata (ratings) and existence confirmation, it poses a privacy risk in environments where message interactions are intended to be confidential.

## Recommendation

Prioritize the upgrade of all instances of Concrete CMS to version 9.5.1 or later to remediate CVE-2026-8239. For defenders, monitor web server logs for high-frequency or anomalous access to the '/ccm/frontend/conversations/get_rating' endpoint, particularly those involving sequential or rapid incrementation of the 'messageId' or 'message_id' query parameters.
