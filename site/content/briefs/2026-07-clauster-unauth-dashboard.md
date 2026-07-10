---
title: Clauster Dashboard Unauthenticated Access Vulnerability
slug: 2026-07-clauster-unauth-dashboard
description: A Clauster instance deployed on a non-loopback address can be accessed unauthenticated, even if password protection is configured, due to auth.enabled defaulting to false. This allows an attacker with network access to gain full control of the dashboard, including listing projects, spawning remote-control bridges, editing files, reading logs, and cloning repositories, ultimately leading to remote code execution in project directories.
date: "2026-07-10T20:41:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - misconfiguration
  - remote-code-execution
  - vulnerability
  - web-application
products:
  - Clauster (<= 0.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Clauster instance bound to a non-loopback address (e.g. 0.0.0.0 or a LAN IP) can serve the entire dashboard and its API without any authentication
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: spawn/stop `claude remote-control` bridges in any project directory... Because bridges run Claude Code against the host's project directories, this is effectively remote code execution in those projects.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h4g2-xfmw-q2c9
iocs:
  - type: url
    value: http://<host>:7621/api/instances
ioc_counts:
  url: 1
---

A high-severity vulnerability (GHSA-h4g2-xfmw-q2c9) has been disclosed in Clauster, a project management and automation tool. Versions up to and including 0.2.1 are affected. The vulnerability allows an unauthenticated attacker with network access to gain full control over the Clauster dashboard and its API, even if the operator believes the instance is password-protected. This occurs when Clauster is bound to a non-loopback address (e.g., `0.0.0.0` or a local area network IP) and the `auth.enabled` configuration flag is left at its default `false` value. This misconfiguration bypasses all intended authentication checks, enabling an attacker to manipulate projects, execute arbitrary code via `claude remote-control` bridges, and potentially exfiltrate sensitive data. Docker deployments are particularly susceptible as the official image binds to `0.0.0.0` by default, and previous documentation did not explicitly advise setting `auth.enabled`.

## Attack Chain

1. Attacker identifies a Clauster instance exposed on a non-loopback network interface (e.g., `0.0.0.0` or a LAN IP).
2. Attacker sends an unauthenticated HTTP GET request to a sensitive API endpoint, such as `http://<host>:7621/api/instances`.
3. The Clauster instance responds with a `200 OK` status code and the requested data, effectively bypassing the intended authentication mechanism due to the `auth.enabled: false` misconfiguration.
4. Attacker gains full control over all Clauster dashboard functionalities, including listing projects, accessing project details, and manipulating configurations.
5. Attacker spawns `claude remote-control` bridges within targeted project directories on the Clauster host.
6. Attacker leverages the `claude remote-control` bridge to execute arbitrary Claude Code, achieving remote code execution (RCE) on the host system within the context of the project.
7. Attacker can then edit `CLAUDE.md`, read bridge logs, or clone configured repositories, leading to data exfiltration or further system compromise.

## Impact

Successful exploitation allows an unauthenticated attacker with network access to achieve full administrative control over the Clauster dashboard. This includes the ability to list projects, spawn and stop `claude remote-control` bridges, edit project files such as `CLAUDE.md`, read bridge logs, and clone repositories where configured. Critically, because `claude remote-control` bridges execute Claude Code against the host's project directories, this misconfiguration effectively grants the attacker remote code execution capabilities on the underlying system. This can lead to complete compromise of the host, data theft, and further network intrusion. Loopback deployments (`127.0.0.1`) are not affected by this specific vulnerability.

## Recommendation

* Immediately update all Clauster instances to the latest patch release once available, as it will enforce stricter configuration validation to prevent this misconfiguration.
* Apply the documented workaround by ensuring `auth.enabled: true` is explicitly set in your `clauster.yml` file or via the `CLAUSTER_AUTH_ENABLED=true` environment variable for all non-loopback deployments.
* Verify that unauthenticated access to `http://<host>:7621/api/instances` returns a `401 Unauthorized` status code after applying the workaround.
