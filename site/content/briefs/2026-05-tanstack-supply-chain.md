---
brief_id: brief-2026-05-tanstack-supply-chain
event_id: brief-2026-05-tanstack-supply-chain
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:af370e944697da9fc3423abb386df0f827130411aacedcc953bb789850435dd1
    summary: exploited:true; KEV CVE-2026-45321
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Compromised @tanstack/* Packages Exfiltrate Credentials via GitHub Actions Exploit
slug: 2026-05-tanstack-supply-chain
description: On 2026-05-11, multiple malicious versions of `@tanstack/*` packages were published to the npm registry due to a chained attack exploiting vulnerabilities in GitHub Actions; the attacker used a compromised GitHub Actions OIDC trusted-publisher binding to publish credential-stealing malware that harvests credentials, exfiltrates data, and propagates the compromise by republishing other packages with the same injection, requiring users who installed affected versions to consider their environment compromised and rotate all credentials.
date: "2026-05-12T00:15:59Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-27T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:tanstack:tanstack\/arktype-adapter:1.166.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/arktype-adapter:1.166.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-router:1.161.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-router:1.161.9:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-start:0.0.4:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-start:0.0.7:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/history:1.161.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/history:1.161.9:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/nitro-v2-vite-plugin:1.154.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/nitro-v2-vite-plugin:1.154.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-devtools:1.166.16:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-devtools:1.166.19:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-ssr-query:1.166.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-ssr-query:1.166.18:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router:1.169.5:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router:1.169.8:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start-client:1.166.51:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start-client:1.166.54:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start:1.167.68:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start:1.167.71:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=4D70655E-6858-5FC9-9F7B-DEDE5131B599&utm_source=rss&utm_medium=rss
tags:
  - supply-chain
  - credential-theft
  - github-actions
vendors:
  - DraftLab
  - GitHub
  - Guardrails AI
  - Microsoft
  - Mistral AI
  - OpenSearch
  - TanStack
  - UiPath
products:
  - '@opensearch-project/opensearch'
  - '@squawk/flightplan'
  - '@squawk/mcp'
  - '@squawk/weather'
  - '@tallyui/connector-medusa'
  - '@tallyui/connector-vendure'
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
  - GitHub Actions
  - guardrails-ai
  - mistralai
  - router
  - Tanstack\/Arktype-Adapter
  - Visual Studio Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    subtechnique_id: T1195.002
    subtechnique_name: Compromise Software Supply Chain
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-45321
    cvss: 9.6
    epss: 0.00043
    kev: true
    kev_status: "true"
references:
  - https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
  - https://github.com/TanStack/router/issues/7383
  - https://github.com/zblgg/configuration
  - https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html
  - https://sploitus.com/exploit?id=4D70655E-6858-5FC9-9F7B-DEDE5131B599&utm_source=rss&utm_medium=rss
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
  - type: domain
    value: filev2.getsession[.]org
  - type: domain
    value: api.masscan[.]cloud
  - type: url
    value: https://git-tanstack.com/transformers.pyz
  - type: domain
    value: api.masscan.cloud
  - type: domain
    value: git-tanstack.com
ioc_counts:
  domain: 8
  url: 3
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
updates:
  - at: "2026-05-12T08:54:32Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
  - at: "2026-05-18T10:01:02Z"
    level: L2
    summary: poc_available; added CVE-2026-45321
    sources:
      - sploitus
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-45321
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

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
