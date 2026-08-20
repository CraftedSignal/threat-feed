---
title: Pipelines-as-Code GitHub App Credential Exfiltration via Header Injection
slug: 2026-08-pipelines-as-code-credential-exfiltration
description: Pipelines-as-Code (CVE-2026-54167) is vulnerable to GitHub App JWT exfiltration because it incorrectly trusts the 'X-GitHub-Enterprise-Host' header to define the API endpoint before validating incoming webhook signatures.
date: "2026-08-20T19:14:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-54167
  - credential-theft
  - red-hat
  - webserver
vendors:
  - Red Hat
products:
  - Pipelines-as-Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can reach the Pipelines-as-Code webhook endpoint can send a crafted GitHub webhook payload containing an installation ID and set X-GitHub-Enterprise-Host to an attacker-controlled host.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials In Files'
    evidence: This can disclose the GitHub App JWT to the attacker-controlled service, allowing the attacker to attempt to mint GitHub App installation access tokens.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f5f4-3hh4-f54m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54167
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Deploy Pipelines-as-Code v0.48.0 patch to address CVE-2026-54167
      owner: IT Operations
      due: 24h
      evidence: The fix is available in v0.48.0.
  mitigation_plan:
    - priority: immediate
      action: Configure ingress/proxy to filter X-GitHub-Enterprise-Host header
      owner: IT Operations
      addresses: CVE-2026-54167
      evidence: Operators should block or strip unexpected X-GitHub-Enterprise-Host headers at the ingress or proxy in front of the Pipelines-as-Code webhook endpoint.
---

Pipelines-as-Code versions prior to 0.48.0 contain a critical vulnerability in the handling of GitHub App authentication during webhook processing. The service improperly trusts the 'X-GitHub-Enterprise-Host' HTTP header to determine the GitHub Enterprise API host for token generation requests. An attacker can supply a malicious, attacker-controlled URL in this header within a crafted webhook payload. Because the controller attempts to generate a GitHub App JWT and request an installation access token before validating the webhook signature or confirming that the Enterprise host corresponds to the target repository, the internal GitHub App JWT is transmitted to the attacker-controlled server. This exposure allows attackers to potentially mint GitHub App installation access tokens, assuming they operate within the window of the JWT's validity and the specific App's permissions. This vulnerability affects installations of OpenShift Pipelines-as-Code across multiple version branches.

## Attack Chain

1. Attacker identifies a target instance of Pipelines-as-Code exposed to the internet.
2. Attacker crafts a malicious GitHub webhook payload containing a valid 'installation.id' associated with the target GitHub App.
3. Attacker includes the 'X-GitHub-Enterprise-Host' header in the HTTP request, pointing to an attacker-controlled listener.
4. The Pipelines-as-Code webhook endpoint receives the payload.
5. The service initiates token generation by reading the malicious 'X-GitHub-Enterprise-Host' header.
6. The service signs a GitHub App JWT and transmits it to the attacker-supplied host before verifying the webhook signature.
7. Attacker captures the GitHub App JWT from the outbound request.
8. Attacker uses the captured JWT to impersonate the GitHub App and mint installation access tokens.

## Impact

Successful exploitation leads to the exfiltration of sensitive GitHub App JWTs, granting the attacker the ability to obtain installation access tokens. This enables unauthorized actors to perform actions within the repository context equivalent to the GitHub App's granted permissions, potentially including code modification, secret exfiltration, or workflow manipulation. The vulnerability impacts all Pipelines-as-Code users utilizing the GitHub App provider model across various versions, specifically those prior to the v0.48.0 security patch.

## Recommendation

* Upgrade to Pipelines-as-Code v0.48.0 or later immediately to include the fix for CVE-2026-54167.
* For ingress/proxy points in front of the webhook endpoint, implement a rule to strip or validate the 'X-GitHub-Enterprise-Host' header; reject requests that contain this header for GitHub.com installations, and strictly allow only known-good hostnames for GitHub Enterprise Server environments.
* If exploitation is suspected, rotate the GitHub App private key immediately and perform an audit of GitHub App installation token usage logs to identify anomalous activity.
* Restrict network access to the webhook endpoint to only trusted IP ranges associated with authorized Git provider sources.
