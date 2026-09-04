---
title: Ted Backdoor Implant in Trojanized HAProxy Binaries
slug: 2026-09-ted-backdoor
description: North Korean state-sponsored actors are deploying a sophisticated Linux backdoor named 'ted' by replacing legitimate HAProxy binaries with trojanized versions to intercept web traffic and execute malicious commands.
date: "2026-09-04T15:44:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux
  - backdoor
  - malware
  - network-security
vendors:
  - HAProxy
products:
  - HAProxy (2.8.12)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Systemd Service
    evidence: The implant overwrites the legitimate crond binary and gives the replacement the creation timestamp of /usr/bin/ssh.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: Output returns on the raw socket under a standard HTTP/1.0 200 OK header, which is what makes the exchange look like ordinary web traffic.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.002
    technique_name: 'Indicator Removal: File Deletion'
    evidence: It strips the keywords tmp, wget, cron and crond from root's bash history and from six system logs.
    confidence_band: high
iocs:
  - type: domain
    value: img.monderhouse.space
  - type: domain
    value: img.smartnords.site
  - type: domain
    value: img.darklights.store
  - type: domain
    value: img.responsive.pstatic.autos
  - type: domain
    value: img.socialteams.store
  - type: domain
    value: img.worksongo.store
  - type: hash_sha256
    value: 72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558
  - type: hash_sha256
    value: 4bb923eb040aa13ca8fd409c31ee4729c60ddff32e350efe1c5a4a9168a065f5
ioc_counts:
  domain: 6
  hash_sha256: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Run file integrity audits on all critical Linux system binaries and load balancer instances.
      owner: SOC
      due: 24h
      evidence: The implant replaces legitimate binaries to hide its activity.
  mitigation_plan:
    - priority: immediate
      action: Replace compromised binary files with known-good versions from official distribution repositories.
      owner: IT Operations
      addresses: Binary-level compromise of HAProxy and system services
      evidence: Upgrading via standard package managers does not remove the trojanized binaries.
---

A previously undocumented Linux toolkit, identified by researchers as 'ted', has been discovered compiled directly into trojanized HAProxy load balancer binaries. This threat involves the replacement of legitimate binaries (including HAProxy 2.8.12, agetty, atd, and polkitd) on compromised Linux servers in South Korea. The implant functions as a stealthy interceptor that monitors inbound web traffic for specific URL and referer patterns, serving altered pages to selected targets. 

When triggered, the ted implant decrements HAProxy connection counters to prevent C2 traffic from appearing in backend logs or load balancer statistics. C2 communication occurs over raw sockets using standard HTTP/1.0 200 OK headers, allowing the operator to beacon, manage files, and execute shell commands. The toolkit also includes a trojanized sshd for password harvesting and employs rigorous anti-forensic measures, including the scrubbing of bash history and tampering with system logs (auth.log and audit/audit.log). Because this is a binary-level compromise rather than a software vulnerability, upgrading the application does not remediate the threat.

## Attack Chain

1. Attacker gains initial code execution on a Linux host, likely through exploitation of a portal or service (e.g., groupware).
2. Attacker verifies root privileges to facilitate the replacement of core system binaries.
3. Attacker replaces legitimate system binaries (HAProxy, crond, sshd, agetty, atd, polkitd) with trojanized versions containing the ted toolkit.
4. Attacker forces the timestamp of the new crond binary to match the existing /usr/bin/ssh file to evade basic integrity monitoring.
5. The implant intercepts incoming web traffic, checking for specific User-Agent, URL, and Referer patterns before serving malicious content.
6. The implant writes C2 command bodies to a named pipe under /tmp and erases the request channel, ensuring no evidence reaches application logs.
7. Attacker executes further commands, beacons, or steals plaintext credentials via the trojanized sshd component.
8. Anti-forensic routines strip keywords like 'tmp', 'wget', and 'cron' from bash history and system logs to hide operational activity.

## Impact

This campaign targets organizations in South Korea's automotive and media sectors. Successful exploitation allows for the covert interception and modification of web traffic, remote command execution, and the harvesting of plaintext credentials. As of September 2026, the activity has been linked to North Korean state-sponsored clusters, with defenders noting that the custom nature of the binary replacement and anti-forensic measures makes detection highly challenging without advanced binary integrity or memory analysis.

## Recommendation

Prioritized actions for detection engineering:
- Perform binary integrity checks on critical system binaries (/usr/sbin/haproxy, /usr/sbin/sshd, /usr/bin/agetty) and compare hashes against known-good vendor builds.
- Implement memory behavioral analysis to detect the presence of injected code or anomalous socket manipulation that circumvents standard connection logging.
- Audit system logs and bash history for missing time gaps or systematic deletion of keywords associated with the ted implant (e.g., 'tmp', 'wget', 'cron').
- Monitor for the creation of anomalous named pipes in /tmp and suspicious files identified in the IOC section, such as /tmp/jasper-log.
- Given that HAProxy 2.8.12 is explicitly targeted, audit all internet-facing load balancers for unauthorized binary modifications regardless of reported version strings.
