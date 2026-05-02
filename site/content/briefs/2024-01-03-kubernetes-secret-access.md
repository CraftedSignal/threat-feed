---
title: Kubernetes Secret Access with Suspicious User Agent
slug: 2024-01-03-kubernetes-secret-access
description: Detects read access to Kubernetes Secrets (`get`/`list`) with a user agent matching a curated set of non-standard or attacker-leaning clients, indicating potential credential access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - credential-access
  - cloud
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://attack.mitre.org/techniques/T1552/007/
  - https://kubernetes.io/docs/concepts/configuration/secret/
rules:
  - title: Kubernetes Secret Access with Suspicious User Agent
    description: Detects read access to Kubernetes secrets with a suspicious user agent, indicating potential credential access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Secret Access with Kali Linux User Agent
    description: Detects read access to Kubernetes secrets with a Kali Linux user agent, indicating potential penetration testing or malicious activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This rule identifies suspicious access patterns to Kubernetes Secrets. Attackers may attempt to retrieve secrets containing sensitive information such as credentials, API keys, and other confidential data. This detection focuses on identifying access attempts originating from clients with non-standard user agents, such as scripting runtimes (Python, Perl, PHP), basic HTTP tools (curl, wget), or those associated with penetration testing distributions (Kali Linux). Legitimate access typically involves stable, purpose-built user agents. This detection helps uncover potential credential access attempts that bypass standard access controls. The rule specifically triggers on `get` and `list` actions against Kubernetes secrets, coupled with a suspicious `user_agent.original` and a populated `source.ip`.

## Attack Chain

1.  Attacker gains initial access to a compromised host or pod within the Kubernetes cluster or an external system with network access to the Kubernetes API server.
2.  The attacker crafts HTTP requests to the Kubernetes API server to enumerate available secrets.
3.  The attacker uses tooling such as `curl`, `wget`, or custom scripts with user agents like `python-requests` or `Go-http-client` to interact with the API.
4.  The attacker sends a `GET` or `LIST` request to the `/api/v1/namespaces/{namespace}/secrets/{name}` endpoint to retrieve specific secrets or list all secrets in a namespace.
5.  The Kubernetes API server authenticates and authorizes the request based on the attacker's assigned RBAC roles, potentially using impersonation.
6.  If authorized, the API server returns the secret data in the response.
7.  The attacker extracts sensitive information like passwords, tokens, or API keys from the retrieved secrets.
8.  The attacker uses the compromised credentials to escalate privileges, move laterally within the cluster, or access external resources.

## Impact

Successful exploitation allows attackers to steal sensitive information stored in Kubernetes secrets, leading to privilege escalation, lateral movement, and unauthorized access to critical systems and data. Compromised credentials can be used to access external cloud resources or internal services. The impact depends on the sensitivity of the secrets, but can include data breaches, service disruptions, and significant financial loss.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Secret get or list with Suspicious User Agent` to your SIEM to detect suspicious access to Kubernetes secrets.
*   Investigate any alerts triggered by the Sigma rule, focusing on the user identity (`user.name`), targeted namespace (`kubernetes.audit.objectRef.namespace`), and source IP (`source.ip`).
*   Baseline expected user agents for legitimate automation and add exceptions to the detection rule for known good traffic.
*   Rotate affected secrets and credentials, revoke tokens, and tighten RBAC if unauthorized access is detected.
*   Block or isolate the source host at the network edge to the API server where appropriate, based on `source.ip`.
*   Monitor `kubernetes.audit.annotations.authorization_k8s_io/decision` to identify unauthorized attempts to access secrets.
