---
title: Unauthenticated Remote Access in argocd-mcp via CVE-2026-82456
slug: 2026-08-argocd-mcp-unauth-access
description: The argocd-mcp component version 0.8.0 insecurely binds its HTTP transport to all network interfaces and lacks authentication for MCP sessions when an API token is present, allowing remote attackers to perform unauthorized Argo CD resource modifications.
date: "2026-08-29T17:40:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:argoproj:argocd-mcp:0.8.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - cloud-native
  - cicd
vendors:
  - Argo Project
products:
  - argocd-mcp (0.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers who can reach the listener can invoke the full tool surface using the operator's stored token.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: Accepts MCP sessions without requiring caller credentials when ARGOCD_API_TOKEN is configured.
    confidence_band: high
cves:
  - id: CVE-2026-82456
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82456
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate argocd-mcp service from untrusted network interfaces.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82456 vulnerability description.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to argocd-mcp and monitor for unauthorized API usage until a patch is applied.
      owner: IT Operations
      addresses: CVE-2026-82456
      evidence: NVD vulnerability disclosure.
---

CVE-2026-82456 describes a critical security vulnerability in argocd-mcp version 0.8.0, an interface component for Argo CD. The software is configured to bind its HTTP transport service to all available network interfaces, including those exposed to external or untrusted networks. Furthermore, the application fails to validate the identity of callers when an ARGOCD_API_TOKEN environment variable is present, effectively trusting any request received by the listener. An attacker with network reachability to the argocd-mcp service can leverage this flaw to impersonate the legitimate operator. By submitting malicious MCP (Model Context Protocol) sessions, an unauthenticated attacker can invoke the full tool surface, resulting in the ability to create new applications, trigger unauthorized synchronization tasks, and modify sensitive Argo CD resources. This vulnerability carries a CVSS v3.1 base score of 10.0, highlighting the severe risk to CI/CD pipeline integrity and infrastructure control.

## Impact

Successful exploitation allows remote, unauthenticated attackers to gain full administrative control over the Argo CD tool surface. This can lead to the deployment of malicious container images, unauthorized modification of production configurations, and complete compromise of the CD pipeline. The target scope includes any environment where argocd-mcp 0.8.0 is deployed with the ARGOCD_API_TOKEN configuration.

## Recommendation

- Immediately restrict network access to the argocd-mcp service using host-based firewalls or network policies to ensure it is only reachable from authorized local contexts.
- Audit logs for unexpected MCP session initiations or API calls originating from unauthorized or external IP addresses.
- Monitor for unauthorized application creation or synchronization tasks within the Argo CD instance that do not correlate with legitimate CI/CD pipeline activity.
- Upgrade to a patched version of argocd-mcp immediately upon release by the Argo Project.
