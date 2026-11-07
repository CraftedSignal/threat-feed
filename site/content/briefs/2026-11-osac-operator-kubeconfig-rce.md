---
brief_id: brief-2026-11-07-osac-operator-kubeconfig-rce
event_id: brief-2026-11-07-osac-operator-kubeconfig-rce
revision: 1
activity_at: "2026-11-07T09:41:29Z"
title: 'osac-operator: Remote code execution and SSRF in console-proxy (CVE-2026-62284)'
slug: 2026-11-osac-operator-kubeconfig-rce
description: The osac-operator console-proxy component fails to sanitize kubeconfig data, potentially allowing Remote Code Execution (RCE) via exec plugins or Server-Side Request Forgery (SSRF) via crafted cluster server definitions.
date: "2026-11-07T09:41:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:osac_project:osac_operator:*:*:*:*:*:*:*:*
vendors:
  - osac-project
products:
  - osac-operator (< 0.0.4)
cves:
  - id: CVE-2026-62284
    epss: 0.00505
    kev_status: "false"
references:
  - https://github.com/osac-project/osac-operator
  - https://github.com/advisories/GHSA-5w5g-j6hw-6p8f
---

The console-proxy's RemoteConfigResolver in osac-operator parses kubeconfig data from Kubernetes Secrets without sanitizing the resulting `rest.Config`. 

1. **Remote Code Execution (RCE):** A kubeconfig containing an `exec` plugin stanza (under `users[].user.exec`) is preserved. When the transport is built, `client-go` invokes the exec plugin, spawning an arbitrary process as the `osac-console-proxy` service account. This is possible for any principal that can create or modify a Secret with the label `osac.openshift.io/remote-cluster-kubeconfig: "true"` in a namespace where the proxy has Secret read access.
2. **SSRF:** A secondary vector exists via attacker-controlled `clusters[].server` definitions, enabling SSRF from within the proxy pod.

Affected configurations include any deployment using remote or auto VM cluster mode.
