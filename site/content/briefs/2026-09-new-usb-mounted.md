---
title: Detection of New USB Storage Device Mounting
slug: 2026-09-new-usb-mounted
description: Detection rule identifies first-time seen USB storage devices mounted on Windows and macOS endpoints to help analysts monitor for potential initial access, lateral movement, or data exfiltration.
date: "2026-09-18T19:19:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - endpoint
  - device-control
  - threat-detection
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1091
    technique_name: Replication Through Removable Media
    evidence: Adversaries exploit these to introduce malware or exfiltrate data, leveraging their plug-and-play nature.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1052
    technique_name: Exfiltration Over Physical Medium
    evidence: The detection rule monitors registry changes for new device names, signaling potential unauthorized access.
    confidence_band: high
references:
  - https://www.elastic.co/docs/solutions/security/manage-elastic-defend/trusted-devices
  - https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend#device-control
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify all unique USB serial numbers connected to endpoints in the last 30 days.
      technique_id: T1091
      data_needed:
        - device.serial_number
        - host.id
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: The detection rule identifies newly seen removable devices by device.serial_number and host.id.
---

This brief concerns a detection capability for monitoring removable media usage across enterprise endpoints. Adversaries frequently leverage USB storage devices to introduce malware, achieve initial access, facilitate lateral movement, or exfiltrate sensitive data by exploiting the plug-and-play nature of modern operating systems. The Elastic detection rule tracks device mount events, specifically monitoring for new combinations of device serial numbers and host identifiers. By identifying devices that have not been previously seen on a specific host within a defined history window, security teams can focus investigations on potentially unauthorized hardware usage. While the presence of a new USB device is not inherently malicious, it serves as a critical indicator for identifying abnormal activity in environments where removable media usage should be tightly controlled.

## Impact

Successful exploitation of removable media can lead to the introduction of malicious payloads into isolated environments, the theft of sensitive internal data, or the facilitation of lateral movement across network segments. Unauthorized use of USB drives poses significant risks to data integrity and organizational security policy compliance.

## Recommendation

Prioritize the implementation of device control policies to restrict unauthorized hardware.

- Deploy the provided logic to track new device serial numbers and host identifiers to your SIEM.
- Establish a process to inventory and register approved company-issued USB devices to reduce noise.
- Review file access and transfer logs immediately following a 'new device' alert to assess if data exfiltration is occurring.
- If a device is identified as malicious, utilize Device Control policies to block the specific serial number across the environment.
- Isolate hosts where unauthorized devices were detected to prevent potential lateral movement or malware propagation.
