---
title: Dronecode PX4 Autopilot MavlinkLogHandler Stack Buffer Overflow DoS (CVE-2026-32743)
slug: 2026-05-px4-autopilot-dos
description: A stack-based buffer overflow vulnerability exists in Dronecode PX4 Autopilot versions up to and including 1.17.0-rc2 that allows an attacker with MAVLink link access to cause a denial of service by creating a deeply nested directory via MAVLink FTP and then requesting the log list, crashing the MAVLink task.
date: "2026-05-08T17:08:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:dronecode:px4_drone_autopilot:*:*:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:alpha1:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:beta1:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:rc2:*:*:*:*:*:*
tags:
  - px4
  - autopilot
  - drone
  - denial-of-service
  - buffer-overflow
vendors:
  - Dronecode
products:
  - Px4_Drone_Autopilot
  - PX4 Autopilot <=1.17.0-rc2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
cves:
  - id: CVE-2026-32743
    cvss: 6.5
    epss: 0.00029
references:
  - https://sploitus.com/exploit?id=995BBC30-CEE5-5D4C-AAAC-4B6A991BB7CF&utm_source=rss&utm_medium=rss
  - https://vulners.com/cve/CVE-2026-32743
  - https://github.com/PX4/PX4-Autopilot/commit/616b25a280e229c24d5cf12a03dbf248df89c474
rules:
  - title: Detect PX4 Autopilot MAVLink FTP Long Directory Creation
    description: Detects the creation of a directory with a path length exceeding 60 bytes via MAVLink FTP, which is a prerequisite for exploiting CVE-2026-32743.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - unknown
  - title: Detect PX4 Autopilot MAVLink Log Request
    description: Detects a MAVLink request for the log list, which is the final step to trigger CVE-2026-32743 after an attacker has created a long directory name.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - network_connection
      - unknown
rules_count: 2
---

CVE-2026-32743 is a stack-based buffer overflow vulnerability affecting Dronecode PX4 Autopilot versions up to and including 1.17.0-rc2. The vulnerability resides in the `MavlinkLogHandler`, where the `LogEntry.filepath` buffer, limited to 60 bytes, is vulnerable to overflowing due to the use of `sscanf()` without a width specifier when parsing log directory paths. An attacker with network access to the flight controller's MAVLink UDP port (default 14550) can exploit this by creating a deeply nested directory exceeding 60 bytes via MAVLink FTP and then triggering the overflow by requesting the log list. This leads to a crash of the MAVLink task, resulting in loss of telemetry and command capability, and a persistent Denial of Service (DoS) until the system is rebooted. This was fixed in commit 616b25a which adds a width specifier to `sscanf`.

## Attack Chain

1.  The attacker establishes a MAVLink connection with the PX4 Autopilot system, typically over UDP port 14550.
2.  MAVLink FTP is utilized to create a new directory inside the `/fs/microsd/log/` directory with a path exceeding 60 bytes. For example, "/fs/microsd/log/" + "A"*70.
3.  The PX4 Autopilot system successfully creates the directory on the SD card.
4.  The attacker sends a `MAV_CMD_REQUEST_LOG_LIST` command (command 261) to the PX4 Autopilot system.
5.  The `MavlinkLogHandler::list()` function is invoked, attempting to read the log directory.
6.  The vulnerable `sscanf(path, "%s", LogEntry.filepath)` function is used without a width limit, copying the oversized path into the undersized `LogEntry.filepath` buffer.
7.  A stack-based buffer overflow occurs, writing 70 bytes into a 60-byte buffer.
8.  The MAVLink task crashes due to the buffer overflow, leading to a loss of telemetry and command capabilities and resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, where the PX4 Autopilot system becomes unmanageable and unresponsive. The MAVLink task crashes which means the flight controller loses telemetry and command capability until a reboot. This can be critical if the drone is in flight, as it will lose its ability to receive commands and potentially lead to a crash.

## Recommendation

*   Upgrade PX4 Autopilot to a version later than 1.17.0-rc2, which includes the fix in commit 616b25a that adds a width specifier to `sscanf`.
*   Monitor network traffic for unusual MAVLink FTP activity, specifically the creation of deeply nested directories with path lengths exceeding 60 bytes within the `/fs/microsd/log/` directory, as this is indicative of CVE-2026-32743 exploitation.
*   Deploy the Sigma rule `Detect PX4 Autopilot MAVLink FTP Long Directory Creation` to detect the creation of overly long directory paths via MAVLink FTP, which is a prerequisite for exploiting CVE-2026-32743.
