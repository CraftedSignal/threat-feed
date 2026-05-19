---
title: Multiple Vulnerabilities in Docker Allow Privilege Escalation and DoS
slug: 2026-05-docker-multiple-vulnerabilities
description: Multiple vulnerabilities in Docker allow a local attacker to execute arbitrary code with administrator privileges, cause a denial-of-service condition, or manipulate data.
date: "2026-05-19T11:06:13Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - docker
  - vulnerability
  - privilege-escalation
  - denial-of-service
vendors:
  - Docker
products:
  - Docker
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1584
rules:
  - title: Detect Suspicious Docker Daemon Activity
    description: Detects suspicious commands executed by the Docker daemon that could indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Docker Build
    description: Detects attempts to build Docker images containing suspicious commands or files.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in Docker that could be exploited by a local attacker. These vulnerabilities could allow an attacker to execute arbitrary code with administrator privileges, cause a denial-of-service (DoS) condition, or manipulate data. The vulnerabilities stem from insufficient validation or improper handling of certain input parameters within Docker. Exploitation requires local access to the system running the Docker daemon. Successful exploitation could lead to complete compromise of the host system, depending on the specific vulnerability triggered. This poses a significant risk to systems running Docker in multi-tenant environments or where untrusted users have local access.

## Attack Chain

1.  Attacker gains local access to the system running the Docker daemon.
2.  Attacker crafts a malicious Dockerfile or uses a compromised container image.
3.  Attacker builds the malicious Dockerfile using the `docker build` command, or runs the compromised container using `docker run`.
4.  The build or run process triggers one of the vulnerabilities within the Docker engine.
5.  If the vulnerability allows arbitrary code execution, the attacker executes code with elevated privileges due to the Docker daemon's permissions.
6.  If the vulnerability leads to a DoS, the Docker daemon crashes or becomes unresponsive.
7.  If the vulnerability allows data manipulation, the attacker modifies container images or other Docker-related data.
8.  The attacker leverages the compromised Docker environment to gain further access to the host system or other containers.

## Impact

Successful exploitation of these vulnerabilities can result in complete compromise of the host system running Docker. Depending on the specific vulnerability, attackers can achieve arbitrary code execution with administrator privileges, leading to data theft, system modification, or deployment of malicious software. A denial-of-service condition can disrupt services and impact the availability of applications running within Docker containers. Data manipulation can lead to integrity issues and potentially allow attackers to inject malicious content into container images, affecting downstream users. The BSI advisory indicates a moderate risk level.

## Recommendation

*   Monitor process creation events for suspicious commands executed by the Docker daemon, as described in the "Detect Suspicious Docker Daemon Activity" Sigma rule.
*   Implement strict access control policies to limit local access to systems running the Docker daemon.
*   Regularly update Docker to the latest version to patch known vulnerabilities.
*   Deploy the "Detect Malicious Docker Build" Sigma rule to identify attempts to build images containing suspicious content.
