---
title: Hard-coded Authentication Credentials in Flow Neuroscience FL-100
slug: 2026-08-flow-neuroscience-hardcoded-creds
description: Flow Neuroscience FL-100 and Halo Neuroscience FL-100 devices contain a hard-coded credential vulnerability that allows an attacker within Bluetooth range to manipulate brain stimulation parameters and bypass safety controls.
date: "2026-08-13T16:52:34Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Flow Neuroscience
products:
  - Flow Neuroscience FL-100
  - Halo Neuroscience FL-100
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An undocumented hard-coded credential, shared by all device units, is authorized to bypass authentication.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-225-01
  - https://www.cve.org/CVERecord?id=CVE-2026-18164
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update firmware on all deployed Flow Neuroscience FL-100 and Halo Neuroscience FL-100 devices.
      owner: IT Operations
      due: 7d
      evidence: Users are encouraged to install the latest firmware updates provided by Flow Neuroscience via the Flow app.
---

Flow Neuroscience has identified a critical security vulnerability, CVE-2026-18164, affecting the FL-100 brain stimulation medical device. The vulnerability is rooted in the use of hard-coded credentials that are shared across all device units. An attacker positioned within Bluetooth range of a vulnerable device can leverage these credentials to bypass authentication mechanisms. Once authenticated, the attacker can manipulate brain stimulation parameters and override safety limit thresholds. This flaw poses a significant risk to the health and safety of patients, as the unauthorized modification of device output could result in unintended medical impact. The issue affects all Flow Neuroscience FL-100 and Halo Neuroscience FL-100 devices with firmware versions released prior to July 2026. Defenders should prioritize applying the vendor-supplied firmware updates via the official mobile application to remediate this authentication bypass.

## Impact

Successful exploitation of this vulnerability allows unauthorized control over medical device settings by an actor within physical Bluetooth range. While there are no reports of active exploitation in the wild, the potential impact includes physical harm to patients due to the manipulation of brain stimulation levels and the disabling of device-level safety overrides. The vulnerability is classified as high-severity, impacting both the Flow Neuroscience and Halo Neuroscience product lines worldwide.

## Recommendation

- Ensure all affected Flow Neuroscience FL-100 and Halo Neuroscience FL-100 units are updated to the latest firmware version released by the manufacturer after July 2026 via the Flow app.
- Implement physical access controls and security awareness training to limit unauthorized proximity to medical devices in healthcare settings.
- Monitor for unauthorized Bluetooth pairing attempts or abnormal device management activity in environments where these units are deployed.
