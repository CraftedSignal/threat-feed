---
brief_id: brief-2026-11-18-smartertools-advisory
event_id: brief-2026-11-18-smartertools-advisory
revision: 1
activity_at: "2026-11-18T22:24:23Z"
title: SmarterTools SmarterMail Security Advisory
slug: 2026-11-smartertools-advisory
description: SmarterTools has released a security update for SmarterMail versions prior to Build 9817 to remediate undisclosed vulnerabilities.
date: "2026-11-18T22:24:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
qa_status:
  verdict: pass
  validation_status: All facts extracted directly from CCCS advisory.
vendors:
  - SmarterTools
products:
  - SmarterMail (< Build 9817)
references:
  - https://cyber.gc.ca/en/alerts-advisories/smartertools-security-advisory-av26-1177
  - https://www.smartertools.com/smartermail/release-notes/current
  - https://www.smartertools.com/smartermail/downloads
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory all SmarterMail installations and upgrade to build 9817.
      owner: IT Operations
      due: 48h
      evidence: SmarterTools security advisory AV26-1177
  mitigation_plan:
    - priority: immediate
      action: Upgrade SmarterMail to build 9817 or later.
      owner: IT Operations
      addresses: Undisclosed vulnerabilities in SmarterMail
      evidence: CCCS advisory AV26-1177
---

## Overview

On November 18, 2026, the Canadian Centre for Cyber Security released an advisory (AV26-1177) regarding undisclosed vulnerabilities affecting SmarterMail. The vulnerability impacts all SmarterMail builds prior to 9817. The vendor has provided release notes and download links for the update.

## Recommendation

Inventory all deployments of SmarterMail within the organization. Upgrade all instances of SmarterMail to build 9817 or later immediately. Monitor the SmarterTools official release notes for further technical details regarding the patched vulnerabilities as they become available.
