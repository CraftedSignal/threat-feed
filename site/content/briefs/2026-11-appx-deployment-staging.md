---
brief_id: brief-2026-11-28-appx-deployment-staging
event_id: brief-2026-11-28-appx-deployment-staging
revision: 1
activity_at: "2026-11-28T01:41:35Z"
title: AppX Located in Known Staging Directory Added to Deployment Pipeline
slug: 2026-11-appx-deployment-staging
description: This rule detects an AppX package added to the Windows AppX deployment server pipeline that is located in a directory commonly used as a staging area.
date: "2026-11-28T01:41:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.stealth
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_in_staging_directory.yml
rules:
  - title: AppX Located in Known Staging Directory Added to Deployment Pipeline
    description: Detects an appx package that was added to the pipeline of the "to be processed" packages that is located in a known folder often used as a staging directory.
    platform: sigma
    severity: high
    data_sources:
      - appxdeployment-server
rules_count: 1
---

## Overview
This rule identifies when an AppX package is added to the "to be processed" pipeline of the Windows AppX deployment server (Event ID 854) from folders frequently used as staging directories.

## Attack Chain
Attackers may use staging directories to host payloads before deployment to evade detection or facilitate malicious execution via the Windows AppX mechanism.

## Impact
Successful identification of these events indicates a potential attempt to deploy unauthorized or malicious AppX packages.

## Recommendation
Monitor Event ID 854 for packages originating from identified staging directories. Investigate the provenance and purpose of any packages flagged by this rule.
