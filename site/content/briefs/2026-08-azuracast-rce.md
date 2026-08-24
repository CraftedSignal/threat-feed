---
title: CVE-2026-76836 - Improper Access Control in AzuraCast Leads to RCE
slug: 2026-08-azuracast-rce
description: An improper access control vulnerability in AzuraCast allows low-privileged users to inject arbitrary commands into Liquidsoap configurations, leading to remote code execution upon backend restart.
date: "2026-08-24T20:06:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - rce
  - access-control
  - vulnerability
vendors:
  - AzuraCast
products:
  - AzuraCast
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: ConfigWriter::writeCustomConfigurationSection() emits those values verbatim into the generated Liquidsoap .liq script, where the process.run() and process.exec() built-ins execute operating system commands.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A station manager holding only the profile permission reaches configuration that the intended boundary reserves for broadcasting operators.
    confidence_band: high
cves:
  - id: CVE-2026-76836
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76836
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch AzuraCast to the vendor-provided security release addressing CVE-2026-76836.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76836
  mitigation_plan:
    - priority: immediate
      action: Review and audit user permissions for the 'Profile' role in AzuraCast to ensure principle of least privilege.
      owner: IT Operations
      addresses: CVE-2026-76836
      evidence: Source document indicates the vulnerability is triggered by unauthorized access to profile management features.
---

CVE-2026-76836 affects AzuraCast and stems from an authorization bypass in the station profile update API. The endpoint 'PUT /api/station/{station_id}/profile/edit' incorrectly allows users with only 'StationPermissions::Profile' to modify sensitive 'backend_config' properties, which are intended to be restricted to users with 'StationPermissions::Broadcasting' privileges. The vulnerable properties include 'custom_config_top', 'custom_config', 'custom_config_pre_playlists', 'custom_config_pre_live', 'custom_config_pre_fade', and 'custom_config_bottom'. When these fields are updated, the 'ConfigWriter' component writes the attacker-controlled input directly into the generated Liquidsoap (.liq) configuration file. Upon a station restart, the Liquidsoap backend executes these values using 'process.run()' or 'process.exec()', enabling remote command execution with the privileges of the Liquidsoap service. This vulnerability is critical for environments where multiple users manage station profiles with limited scope.

## Attack Chain

1. Attacker authenticates to the AzuraCast instance as a user holding the 'StationPermissions::Profile' permission.
2. Attacker sends a 'PUT' request to '/api/station/{station_id}/profile/edit'.
3. Attacker includes malicious shell commands within the 'custom_config' or associated fields in the JSON request body.
4. The application deserializes the input, failing to enforce field-level permissions for the station profile entity.
5. The application writes the malicious payload into the generated Liquidsoap configuration script.
6. The application sets the 'needs_restart' flag, which triggers the backend sync task.
7. The Liquidsoap service reloads the configuration, executing the injected shell commands via 'process.run()' or 'process.exec()'.
8. Final objective: Remote command execution on the host server.

## Impact

Successful exploitation grants an unauthorized user remote command execution capabilities on the host running the AzuraCast instance. This can lead to full system compromise, data exfiltration, or lateral movement within the network. The severity is assessed at 8.8 (CVSS v3.1), reflecting high impact on confidentiality, integrity, and availability for affected web-based radio management installations.

## Recommendation

* Update AzuraCast to the latest patched version that enforces strict 'StationPermissions::Broadcasting' checks on the 'backend_config' entity.
* Restrict API access for the 'Profile' permission group to prevent access to configuration endpoints until the software is patched.
* Monitor server logs for unexpected execution of shell commands stemming from the liquidsoap process or the user account running the AzuraCast service.
