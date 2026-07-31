---
title: SSRF and Credential Exfiltration in vault-secrets-webhook
slug: 2026-07-vault-secrets-webhook-ssrf
description: The vault-secrets-webhook is vulnerable to SSRF and ServiceAccount token theft due to unvalidated annotation handling, allowing attackers to exfiltrate JWTs via unauthorized outbound requests.
date: "2026-07-31T19:20:21Z"
type: threat
types:
  - threat
severities:
  - critical
vendors:
  - Banzai Cloud
products:
  - vault-secrets-webhook (1.22.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attack happens at admission time in the webhook server process, not in a user pod, and requires no special privileges beyond ConfigMap or Secret create/update rights.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Exfiltrate ServiceAccount JWTs for any SA in their namespace, which can be replayed against the real Vault server to read secrets the SA's role is authorized to access
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: An attacker who can create ConfigMaps or Secrets in a watched namespace can cause the webhook process to make arbitrary outbound HTTP connections and exfiltrate ServiceAccount JWTs.
    confidence_band: high
cves:
  - id: CVE-2026-54725
    cvss: 9.6
references:
  - https://github.com/advisories/GHSA-r2v3-8gwf-7ghm
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54725
---

The Banzai Cloud vault-secrets-webhook (versions <= 1.22.2) contains a critical vulnerability (CVE-2026-54725) that enables Server-Side Request Forgery (SSRF) and cluster-wide privilege escalation. The webhook improperly validates the `vault.security.banzaicloud.io/vault-addr` annotation on Kubernetes ConfigMaps and Secrets. When an attacker creates or updates these resources with a `vault:` prefix, the webhook's admission handler synchronously invokes a request to the user-supplied URL. 

Beyond the SSRF, the webhook holds excessive cluster-wide `serviceaccounts/token:create` permissions. When combined with the `vault-serviceaccount` annotation, an attacker can coerce the webhook to generate a token for any ServiceAccount and transmit that JWT to an attacker-controlled server. This enables attackers to impersonate authorized ServiceAccounts and access sensitive data from the Vault instance. The attack occurs during the admission review process, making it highly effective for users with standard namespace access rights.

## Attack Chain

1. Attacker creates or updates a ConfigMap or Secret in a namespace monitored by the vault-secrets-webhook.
2. Attacker injects the `vault.security.banzaicloud.io/vault-addr` annotation with an attacker-controlled URL or internal metadata endpoint (e.g., 169.254.169.254).
3. Attacker specifies `vault.security.banzaicloud.io/vault-serviceaccount` pointing to a target ServiceAccount to be exfiltrated.
4. Webhook admission handler intercepts the request and parses the malicious annotations during the admission review cycle.
5. Webhook uses its cluster-wide RBAC permissions to call `CoreV1().ServiceAccounts().CreateToken` for the requested ServiceAccount.
6. Webhook initiates a synchronous HTTP request via `vault.NewClientFromConfigWithContext` to the attacker-defined URL.
7. The sensitive ServiceAccount JWT is transmitted via the Authorization header to the attacker-controlled server.
8. Attacker replays the captured JWT against the Vault instance to access unauthorized secrets.

## Impact

Successful exploitation allows for the exfiltration of high-privilege ServiceAccount JWTs, leading to complete credential compromise of Vault-managed secrets. Attackers can leverage the webhook's privileged network position to probe internal network infrastructure and cloud metadata services, potentially escalating access within the cloud environment. This vulnerability affects all environments running the vault-secrets-webhook where users have standard resource creation permissions in monitored namespaces.

## Recommendation

* Patch the vault-secrets-webhook to version 1.22.3 or higher to incorporate input validation for the vault-addr annotation and improved security controls.
* Audit current ClusterRole definitions for the vault-secrets-webhook to restrict `serviceaccounts/token:create` permissions to the minimum necessary scope.
* Use network policies to restrict egress traffic from the webhook pod to only allow communication with known, legitimate Vault server endpoints.
* Monitor Kubernetes audit logs for ConfigMap and Secret operations containing the specified vault-security annotations.
