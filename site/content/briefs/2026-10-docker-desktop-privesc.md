---
title: Docker Desktop Local Privilege Escalation Vulnerability
slug: 2026-10-docker-desktop-privesc
description: A local privilege escalation vulnerability in Docker Desktop for Windows allows a local attacker to execute arbitrary code with administrative privileges.
date: "2026-10-12T18:30:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Docker
products:
  - Docker Desktop
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in Docker Desktop ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3851
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Windows systems running Docker Desktop to identify the attack surface.
      owner: IT Operations
      due: 24h
      evidence: Advisory confirms Docker Desktop as the affected product.
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply official patches from Docker to all installations.
      owner: IT Operations
      addresses: Docker Desktop Windows vulnerability
      evidence: Advisory notifies of a vulnerability requiring mitigation.
---

The German Federal Office for Information Security (BSI) has reported a security vulnerability in Docker Desktop that permits a local attacker to achieve arbitrary code execution with administrative privileges on Windows systems. This flaw represents a significant risk for environments where multiple users or processes operate on the same host, as an attacker with low-privilege access can elevate their permissions to the level of the system administrator. Organizations running Docker Desktop on Windows should evaluate their exposure and prioritize updates as soon as they become available from the vendor. Given the nature of the vulnerability, it primarily impacts the local host environment rather than containerized workloads directly, though it provides a pathway for an attacker to compromise the underlying host OS and all associated security controls.

## Impact

The vulnerability poses a severe risk to the integrity and confidentiality of compromised Windows workstations and servers. A successful exploit allows a local attacker to bypass existing security boundaries, granting full administrative control over the host. This can lead to the installation of persistent backdoors, access to sensitive credentials stored on the machine, and potential lateral movement within the network. All environments deploying Docker Desktop on Windows are considered at risk if the software is not patched.

## Recommendation

Prioritize the deployment of updates for Docker Desktop on Windows as soon as the vendor issues a fix. Monitor internal software inventory to identify all systems running affected versions of Docker Desktop and ensure they are included in the immediate patching cycle.
