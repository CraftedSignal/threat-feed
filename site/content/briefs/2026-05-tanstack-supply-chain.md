---
title: Compromised @tanstack/* Packages Exfiltrate Credentials via GitHub Actions Exploit
slug: 2026-05-tanstack-supply-chain
description: On 2026-05-11, multiple malicious versions of `@tanstack/*` packages were published to the npm registry due to a chained attack exploiting vulnerabilities in GitHub Actions; the attacker used a compromised GitHub Actions OIDC trusted-publisher binding to publish credential-stealing malware that harvests credentials, exfiltrates data, and propagates the compromise by republishing other packages with the same injection, requiring users who installed affected versions to consider their environment compromised and rotate all credentials.
date: "2026-05-12T00:15:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - github-actions
vendors:
  - TanStack
products:
  - '@tanstack/arktype-adapter'
  - '@tanstack/eslint-plugin-router'
  - '@tanstack/eslint-plugin-start'
  - '@tanstack/history'
  - '@tanstack/nitro-v2-vite-plugin'
  - '@tanstack/react-router'
  - '@tanstack/react-router-devtools'
  - '@tanstack/react-router-ssr-query'
  - '@tanstack/react-start'
  - '@tanstack/react-start-client'
  - '@tanstack/react-start-rsc'
  - '@tanstack/react-start-server'
  - '@tanstack/router-cli'
  - '@tanstack/router-core'
  - '@tanstack/router-devtools'
  - '@tanstack/router-devtools-core'
  - '@tanstack/router-generator'
  - '@tanstack/router-plugin'
  - '@tanstack/router-ssr-query-core'
  - '@tanstack/router-utils'
  - '@tanstack/router-vite-plugin'
  - '@tanstack/solid-router'
  - '@tanstack/solid-router-devtools'
  - '@tanstack/solid-router-ssr-query'
  - '@tanstack/solid-start'
  - '@tanstack/solid-start-client'
  - '@tanstack/solid-start-server'
  - '@tanstack/start-client-core'
  - '@tanstack/start-fn-stubs'
  - '@tanstack/start-plugin-core'
  - '@tanstack/start-server-core'
  - '@tanstack/start-static-server-functions'
  - '@tanstack/start-storage-context'
  - '@tanstack/valibot-adapter'
  - '@tanstack/virtual-file-routes'
  - '@tanstack/vue-router'
  - '@tanstack/vue-router-devtools'
  - '@tanstack/vue-router-ssr-query'
  - '@tanstack/vue-start'
  - '@tanstack/vue-start-client'
  - '@tanstack/vue-start-server'
  - '@tanstack/zod-adapter'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
  - https://github.com/TanStack/router/issues/7383
  - https://github.com/zblgg/configuration
iocs:
  - type: domain
    value: filev2.getsession.org
  - type: domain
    value: seed1.getsession.org
  - type: domain
    value: seed2.getsession.org
  - type: domain
    value: seed3.getsession.org
  - type: url
    value: https://litter.catbox.moe/h8nc9u.js
  - type: url
    value: https://litter.catbox.moe/7rrc6l.mjs
ioc_counts:
  domain: 4
  url: 2
rules:
  - title: Detect router_init.js creation during npm install
    description: Detects the creation of router_init.js, a malicious payload dropped by compromised @tanstack/* packages, during npm install or similar package installation processes.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1608
    data_sources:
      - file_event
      - windows
  - title: Detect Outbound Connections to Oxen Network Domains
    description: Detects outbound network connections to domains associated with the Session/Oxen messenger network, used for exfiltration by compromised @tanstack/* packages.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 `@tanstack/*` packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for `TanStack/router`, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a `pull_request_target` "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart. This supply chain attack highlights the risks of compromised CI/CD pipelines and the potential for widespread credential theft.

## Attack Chain

1. The attacker exploited a `pull_request_target` "Pwn Request" misconfiguration in the `TanStack/router` repository.
2. The attacker performed GitHub Actions cache poisoning across the fork↔base trust boundary, injecting malicious code into the cache.
3. The attacker extracted the OIDC token from the Actions runner process memory.
4. Using the compromised OIDC token, the attacker published malicious versions of `@tanstack/*` packages to the npm registry via the legitimate GitHub Actions OIDC trusted-publisher binding.
5. Upon installation of a malicious package version, the `router_init.js` payload (~2.3 MB obfuscated) executes.
6. The payload harvests credentials from AWS, GCP, Kubernetes, HashiCorp Vault, npm, GitHub, and SSH keys.
7. The harvested data is exfiltrated over the Session/Oxen messenger network to `filev2.getsession.org`, `seed{1,2,3}.getsession.org`.
8. The attacker enumerates packages maintained by the victim and republishes them with the same injection, propagating the compromise.

## Impact

Any developer or CI environment that ran `npm install`, `pnpm install`, or `yarn install` against an affected version on 2026-05-11 should be considered compromised. All credentials accessible to the install process, including AWS, GCP, Kubernetes, Vault, npm, GitHub, and SSH keys, should be rotated immediately. Cloud audit logs should be reviewed for activity originating from the affected hosts during and after the install window. The malicious packages also attempt to propagate the compromise to other packages maintained by the victim.

## Recommendation

*   Inspect the manifest of any pinned `@tanstack/*` version for the malicious `optionalDependencies` entry as described in the Detection section.
*   Block connections to the exfiltration domains `filev2.getsession.org`, `seed1.getsession.org`, `seed2.getsession.org`, and `seed3.getsession.org` at the network level.
*   Deploy the Sigma rules to detect the presence of the malicious `router_init.js` file.
*   Pin every `@tanstack/*` dependency to a known-good version published before 2026-05-11 19:00 UTC, as described in the Workarounds section.
