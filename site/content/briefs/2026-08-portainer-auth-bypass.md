---
title: Unauthenticated Admin Takeover in Portainer Initialization
slug: 2026-08-portainer-auth-bypass
description: An authentication bypass vulnerability in Portainer allows unauthenticated attackers to hijack uninitialized instances via the /api/restore and /api/users/admin/init endpoints.
date: "2026-08-28T21:14:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:portainer:portainer:*:*:*:*:*:*:*:*
  - cpe:2.3:a:portainer:portainer:*:*:*:*:community:*:*:*
tags:
  - authentication-bypass
  - cve-2026-55761
  - portainer
  - container-security
vendors:
  - Portainer
products:
  - Portainer CE (2.39.0 <= v < 2.39.4, < 2.43.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /api/restore and /api/users/admin/init endpoints remain unauthenticated for a five-minute window upon startup in uninitialized instances.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Portainer CE typically runs with access to the Docker socket; an attacker with Portainer admin access can use container creation APIs to mount the host filesystem and execute commands as root.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The compromised Portainer admin account has credentials and API access for every Docker host, Kubernetes cluster, and edge agent registered in that instance, including any stored registry credentials.
    confidence_band: high
cves:
  - id: CVE-2026-55761
    cvss: 5.9
    epss: 0.00493
references:
  - https://github.com/advisories/GHSA-x626-fcwx-f5pc
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all Portainer instances to 2.39.4 or 2.43.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-55761 documentation mandates these versions for the security fix.
  mitigation_plan:
    - priority: immediate
      action: Use --admin-password flag for all new deployments
      owner: IT Operations
      addresses: CVE-2026-55761
      evidence: Source workaround documentation provided by Portainer.
---

Portainer is vulnerable to an authentication bypass during the five-minute initialization window that occurs when a new instance starts without an administrator account. The endpoints `/api/restore` and `/api/users/admin/init` were designed to be public to facilitate initial setup; however, they lack proper authentication, allowing any network-reachable attacker to either restore a malicious database containing pre-configured attacker credentials or directly create a new administrative user. This vulnerability, tracked as CVE-2026-55761, affects Portainer CE versions in the 2.39.x branch prior to 2.39.4 and 2.43.x branch prior to 2.43.0. Versions prior to 2.39.0 are end-of-life and remain vulnerable. Successful exploitation results in full administrative control over the Portainer instance, which typically grants root-level access to the underlying Docker host or Kubernetes environment, along with access to all stored secrets and registered edge agents.

## Attack Chain

1. Attacker performs network scanning to identify uninitialized Portainer instances reachable over the network.
2. Attacker restarts the identified Portainer instance or waits for a restart to trigger the five-minute initialization window.
3. Attacker sends a POST request to the `/api/users/admin/init` endpoint to create a new, attacker-controlled administrative account.
4. Alternatively, attacker sends a POST request to the `/api/restore` endpoint to overwrite the database with a crafted archive containing malicious administrative credentials.
5. Attacker authenticates to the Portainer web interface using the newly created credentials.
6. Attacker leverages Portainer's administrative permissions to deploy a container with host filesystem mounting capabilities.
7. Attacker executes commands within the container to escape to the host OS with root privileges.
8. Attacker exfiltrates stored registry credentials, API keys, and environment variables from the Portainer instance.

## Impact

Successful exploitation grants an attacker full administrative access to a Portainer instance, enabling them to compromise every registered Docker host, Kubernetes cluster, or edge agent. Because Portainer typically manages the Docker socket (`/var/run/docker.sock`), an attacker can easily execute arbitrary code on the underlying host, leading to full system compromise. Furthermore, the attacker gains access to all managed credentials, environment variables, and stored secrets within the environment, providing significant opportunities for lateral movement and long-term persistence.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade all Portainer instances to the fixed versions (2.39.4 for the 2.39.x branch or 2.43.0 for the 2.43.x branch) to implement the required X-Setup-Token header authentication for initialization endpoints.
- For new deployments, use the `--admin-password` or `--admin-password-file` configuration flags to provision the administrator account during initial startup, which prevents the instance from entering the vulnerable uninitialized state.
- Implement network-layer restrictions (e.g., firewall rules, VPC security groups) to isolate Portainer instances from untrusted networks until the initial setup process is complete and an admin account is established.
- Audit existing Portainer deployments for the presence of unauthorized administrative accounts or anomalous activity originating from local account creation events.
