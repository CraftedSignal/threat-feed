---
title: Suspicious Redis Server Process Execution
slug: 2026-08-suspicious-redis-activity
description: Detection of unauthorized system shell and utility execution originating from Redis server processes indicative of post-exploitation activity or sandbox escapes like CVE-2022-0543.
date: "2026-08-07T15:17:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*
tags:
  - redis
  - linux
  - post-exploitation
  - cve-2022-0543
vendors:
  - Redis
products:
  - redis-server
  - redis-sentinel
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The following analytic detects Redis processes spawning a system shell command.
    confidence_band: high
cves:
  - id: CVE-2022-0543
    cvss: 10
    epss: 0.99277
references:
  - https://thesecmaster.com/how-to-fix-cve-2022-0543-a-critical-lua-sandbox-escape-vulnerability-in-redis/
  - https://www.bleepingcomputer.com/news/security/new-p2pinfect-worm-malware-targets-linux-and-windows-redis-servers/
rules:
  - title: Detect Suspicious Redis Process Execution
    description: Detects redis-server or redis-sentinel processes spawning shell commands or common utility binaries.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
      - T1505
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for suspicious process lineage involving Redis.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic rule provided in the brief.
  mitigation_plan:
    - priority: immediate
      action: Review and patch all Redis server instances for CVE-2022-0543.
      owner: IT Operations
      addresses: CVE-2022-0543
      evidence: Source documentation identifies CVE-2022-0543 as a primary exploitation vector for Redis.
---

This threat brief focuses on the detection of malicious activity involving Redis server and sentinel processes. Attackers target Redis to gain remote code execution, often leveraging vulnerabilities such as the Lua sandbox escape identified in CVE-2022-0543 or through misconfigured instances. Once initial access is achieved, attackers use the Redis process to spawn shell environments or external utility binaries to facilitate further post-exploitation actions. These actions include persistence, privilege escalation, and establishing command-and-control communication. This behavior is highly irregular for legitimate Redis operations and indicates a compromised Linux host requiring immediate investigation.

## Attack Chain

1. Attacker identifies an internet-facing Redis server with weak authentication or targets a vulnerable version (e.g., CVE-2022-0543).
2. Attacker interacts with the Redis instance, often through a malicious Lua script or by leveraging the Redis replication feature to write arbitrary files.
3. The Redis process context executes the injected payload, leading to an initial foothold on the Linux host.
4. The Redis parent process invokes a system shell (e.g., bash, sh, zsh) or system utility (e.g., curl, wget, python, socat).
5. The spawned shell or utility executes commands to download secondary stages or malicious scripts from remote infrastructure.
6. Attacker establishes persistence by modifying system configuration files or creating cron jobs.
7. Attacker performs privilege escalation or initiates exfiltration, utilizing the hijacked Redis process as a launch point.
8. Final objective is achieved, such as ransomware deployment, credential theft, or full system compromise.

## Impact

Successful exploitation of Redis servers leads to unauthorized remote code execution, enabling attackers to gain full control over the underlying Linux host. This can result in data exfiltration, service disruption, and the use of the compromised server as a pivot point for lateral movement within the network. In the case of botnet malware like P2PInfect, these compromises facilitate the wide-scale propagation of malicious payloads across Linux environments.

## Recommendation

* Enable Sysmon for Linux (Event ID 1) and ensure process lineage (parent-child relationship) and command-line arguments are ingested into your security monitoring platform.
* Deploy the Sigma rule provided in this brief to detect instances where redis-server or redis-sentinel spawn unauthorized shell or utility processes.
* Restrict network access to Redis server ports (default 6379) to authorized internal networks only; do not expose Redis directly to the internet.
* Patch all Redis instances to resolve CVE-2022-0543 and maintain updated versions to mitigate known exploitation vectors.
