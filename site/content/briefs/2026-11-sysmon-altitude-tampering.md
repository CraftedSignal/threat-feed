---
brief_id: brief-2026-11-18-sysmon-altitude-tampering
event_id: brief-2026-11-18-sysmon-altitude-tampering
revision: 1
activity_at: "2026-11-18T13:51:20Z"
title: Sysmon Driver Altitude Tampering
slug: 2026-11-sysmon-altitude-tampering
description: Unauthorized modification of the Sysmon driver altitude registry key can prevent the driver from loading at system boot, effectively impairing Sysmon monitoring capabilities.
date: "2026-11-18T13:51:20Z"
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
  - attack.defense-impairment
  - attack.t1685
affected_os:
  - Windows
references:
  - https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650
  - https://youtu.be/zSihR3lTf7g
  - https://github.com/trustedsec/SysmonCommunityGuide/blob/557dbd51b98952bc26f698620e48dfc7833b5cf0/chapters/the-sysmon-driver.md
  - https://medium.com/@matterpreter/shhmon-silencing-sysmon-via-driver-unload-682b5be57650
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.yml
rules:
  - title: Sysmon Driver Altitude Change
    description: Detects changes in Sysmon driver altitude value. If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview

The Sysmon driver altitude registry key determines the load order of the Sysmon driver in the Windows boot process. If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot. This technique is used to impair defensive visibility by preventing Sysmon from starting.

## Impact

Successful modification prevents Sysmon from starting upon system boot, creating a gap in security logging and visibility.

## Recommendation

- Deploy the provided Sigma rule to monitor registry modifications targeting the Sysmon altitude key.
- Audit existing values of the registry path associated with the Sysmon driver altitude to ensure they reflect the legitimate default value.
