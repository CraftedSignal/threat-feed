---
title: Hard-coded Credentials in Agnaistic Agnai
slug: 2026-10-agnai-hardcoded-creds
description: Agnaistic Agnai versions 1.0.555 and earlier contain hard-coded administrative credentials and a static JWT secret, enabling unauthenticated account takeover and configuration manipulation.
date: "2026-10-11T14:01:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:agnaistic:agnai:*:*:*:*:*:*:*:*
vendors:
  - Agnaistic
products:
  - agnai (<= 1.0.555)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Unauthenticated attackers can log in as admin.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: Agnaistic agnai through 1.0.555 contains a hard-coded credentials vulnerability in self-host.docker-compose.yml.
    confidence_band: high
cves:
  - id: CVE-2026-108753
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108753
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit Agnai deployments for use of default credentials defined in self-host.docker-compose.yml.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108753 advisory
  mitigation_plan:
    - priority: immediate
      action: Rotate administrative passwords and JWT signing secrets for all Agnai instances.
      owner: IT Operations
      addresses: CVE-2026-108753
      evidence: Source identifies hard-coded credentials as the primary vulnerability.
---

Agnaistic Agnai through version 1.0.555 is vulnerable to a hard-coded credentials flaw originating from the `self-host.docker-compose.yml` file. This configuration file ships with a fixed, publicly known administrative password and a static JWT signing secret. Because these secrets are predictable and embedded within the distribution's configuration template, any deployment using the default settings is susceptible to full administrative compromise by an unauthenticated attacker. This flaw allows malicious actors to authenticate as the administrator, generate forged JSON Web Tokens (JWTs) with administrative claims, perform unauthorized password resets, and gain complete control over the server configuration. The vulnerability is rated with a CVSS v3.1 base score of 9.4, highlighting the significant risk to deployments that do not explicitly rotate these secrets upon initial configuration.

## Impact

Successful exploitation allows unauthenticated attackers to obtain full administrative control over the affected Agnai server. This grants the attacker the ability to manage all user accounts, modify server-wide settings, and access potentially sensitive data stored within the application instance. Organizations relying on default deployment configurations are at immediate risk of total service compromise.

## Recommendation

Prioritize remediation for all deployments of Agnai version 1.0.555 and earlier.
* Audit all current Agnai deployments to determine if default credentials or the default JWT secret are in use.
* Update to a version where these credentials are no longer hard-coded or manually rotate the admin password and JWT secret immediately.
* Restrict network access to administrative interfaces to trusted IP addresses until secrets are properly rotated.
* Monitor application access logs for anomalous administrative login events from unknown IP addresses, particularly those following a sequence of password resets or configuration changes.
