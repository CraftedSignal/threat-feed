---
title: TeamPCP Multi-Ecosystem Supply Chain Attack
slug: 2026-05-teampcp-supply-chain
description: TeamPCP is conducting a multi-ecosystem supply chain attack targeting the open-source ecosystem, specifically NPM packages, GitHub Actions, and VSCode extensions, to harvest credentials, exfiltrate sensitive data, and establish persistent access on infected systems via a Python-based backdoor.
date: "2026-05-19T08:38:35Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - credential-theft
  - persistence
vendors:
  - GitHub
  - NPM
  - VSCode
  - antv
products:
  - actions-cool/issues-helper
  - nrwl.angular-console (18.95.0)
  - '@antv/a8'
  - '@antv/adjust'
  - '@antv/algorithm'
  - '@antv/async-hook'
  - '@antv/attr'
  - '@antv/ava'
  - '@antv/ava-react'
  - '@antv/awards'
  - '@antv/calendar-heatmap'
  - '@antv/chart-linter'
  - '@antv/chart-node-g6'
  - '@antv/chart-visualization-skills'
  - '@antv/ckb'
  - '@antv/color-schema'
  - '@antv/color-util'
  - '@antv/component'
  - '@antv/coord'
  - '@antv/d3-color'
  - '@antv/d3-interpolate'
  - '@antv/data-samples'
  - '@antv/data-set'
  - '@antv/data-wizard'
  - '@antv/dipper-component'
  - '@antv/dipper-hooks'
  - '@antv/dipper-map'
  - '@antv/dom-util'
  - '@antv/dumi-theme-antv'
  - '@antv/dw-analyzer'
  - '@antv/dw-random'
  - '@antv/dw-transform'
  - '@antv/dw-util'
  - '@antv/event-emitter'
  - '@antv/expr'
  - '@antv/f-charts'
  - '@antv/f-engine'
  - '@antv/f-lottie'
  - '@antv/f-my'
  - '@antv/f-react'
  - '@antv/f-test-utils'
  - '@antv/f-vue'
  - '@antv/f-wx'
  - '@antv/f2'
  - '@antv/f2-algorithm'
  - '@antv/f2-canvas'
  - '@antv/f2-context'
  - '@antv/f2-graphic'
  - '@antv/f2-my'
  - '@antv/f2-react'
  - '@antv/f2-site'
  - '@antv/f2-vue'
  - '@antv/f2-wordcloud'
  - '@antv/f2-wx'
  - '@antv/f6'
  - '@antv/f6-alipay'
  - '@antv/f6-core'
  - '@antv/f6-element'
  - '@antv/f6-hammerjs'
  - '@antv/f6-plugin'
  - '@antv/f6-ui'
  - '@antv/f6-wx'
  - '@antv/g6'
  - '@antv/g-base'
  - '@antv/g-camera-api'
  - '@antv/g-canvas'
  - '@antv/g-canvaskit'
  - '@antv/g-compat'
  - '@antv/g-components'
  - '@antv/g-css-layout-api'
  - '@antv/g-css-typed-om-api'
  - '@antv/g-device-api'
  - '@antv/g-dom-mutation-observer-api'
  - '@antv/g-gesture'
  - '@antv/g-image-exporter'
  - '@antv/g-layout-blocklike'
  - '@antv/g-lite'
  - '@antv/g-lottie-player'
  - '@antv/g-math'
  - '@antv/g-mobile'
  - '@antv/g-mobile-canvas'
  - '@antv/g-mobile-canvas-element'
  - '@antv/g-mobile-svg'
  - '@antv/g-mobile-webgl'
  - '@antv/g-pattern'
  - '@antv/g-perf'
  - '@antv/g-plugin-3d'
  - '@antv/g-plugin-a11y'
  - '@antv/g-plugin-annotation'
  - '@antv/g-plugin-box2d'
  - '@antv/g-plugin-canvas-path-generator'
  - '@antv/g-plugin-canvas-picker'
  - '@antv/g-plugin-canvas-renderer'
  - '@antv/g-plugin-canvaskit-renderer'
  - '@antv/g-plugin-control'
  - '@antv/g-plugin-css-select'
  - '@antv/g-plugin-device-renderer'
  - '@antv/g-plugin-dom-interaction'
  - '@antv/g-plugin-dragndrop'
  - '@antv/g-plugin-gesture'
  - '@antv/g-plugin-gpgpu'
  - '@antv/g-plugin-html-renderer'
  - '@antv/g-plugin-image-loader'
  - '@antv/g-plugin-matterjs'
  - '@antv/g-plugin-mobile-interaction'
  - '@antv/g-plugin-physx'
  - '@antv/g-plugin-rough-canvas-renderer'
  - '@antv/g-plugin-rough-svg-renderer'
  - '@antv/g-plugin-svg-picker'
  - '@antv/g-plugin-svg-renderer'
  - '@antv/g-plugin-webgl-device'
  - '@antv/g-plugin-webgl-renderer'
  - '@antv/g-plugin-webgpu-device'
  - '@antv/g-plugin-yoga'
  - '@antv/g-plugin-zdog-canvas-renderer'
  - '@antv/g-plugin-zdog-svg-renderer'
  - '@antv/g-shader-components'
  - '@antv/g-svg'
  - '@antv/g-web-animations-api'
  - '@antv/g-web-components'
  - '@antv/g-webgl'
  - '@antv/g-webgl-compute'
  - '@antv/g-webgpu'
  - '@antv/g-webgpu-compiler'
  - '@antv/g-webgpu-core'
  - '@antv/g-webgpu-engine'
  - '@antv/g-webgpu-raytracer'
  - '@antv/g-webgpu-unitchart'
  - '@antv/g2'
  - '@antv/g2-brush'
  - '@antv/g2-extension-3d'
  - '@antv/g2-extension-ava'
  - '@antv/g2-extension-plot'
  - '@antv/g2-plugin-slider'
  - '@antv/g2-ssr'
  - '@antv/g2plot'
  - '@antv/g2plot-schemas'
  - '@antv/g6-alipay'
  - '@antv/g6-cli'
  - '@antv/g6-core'
  - '@antv/g6-editor'
  - '@antv/g6-element'
  - '@antv/g6-extension-3d'
  - '@antv/g6-extension-react'
  - '@antv/g6-mobile'
  - '@antv/g6-pc'
  - '@antv/g6-plugin'
  - '@antv/g6-plugin-map-view'
  - '@antv/g6-plugins'
  - '@antv/g6-react-node'
  - '@antv/g6-ssr'
  - '@antv/g6-wx'
  - '@antv/gatsby-theme'
  - '@antv/geo-coord'
  - '@antv/gi-assets-advance'
  - '@antv/gi-assets-algorithm'
  - '@antv/gi-assets-basic'
  - '@antv/gi-assets-galaxybase'
  - '@antv/gi-assets-graphscope'
  - '@antv/gi-assets-hugegraph'
  - '@antv/gi-assets-janusgraph'
  - '@antv/gi-assets-neo4j'
  - '@antv/gi-assets-scene'
  - '@antv/gi-assets-tugraph'
  - '@antv/gi-assets-tugraph-analytics'
  - '@antv/gi-assets-xlab'
  - '@antv/gi-cli'
  - '@antv/gi-common-components'
  - '@antv/gi-mock-data'
  - '@antv/gi-public-data'
  - '@antv/gi-sdk'
  - '@antv/gi-sdk-app'
  - '@antv/gi-theme-antd'
  - '@antv/github-config-cli'
  - '@antv/gl-matrix'
  - '@antv/gpt-vis'
  - '@antv/gpt-vis-ssr'
  - '@antv/graphin'
  - '@antv/graphin-components'
  - '@antv/graphin-graphscope'
  - '@antv/graphin-icons'
  - '@antv/graphlib'
  - '@antv/hierarchy'
  - '@antv/infographic'
  - '@antv/insight-component'
  - '@antv/interaction'
  - '@antv/istanbul'
  - '@antv/knowledge'
  - '@antv/l7'
affected_os:
  - macos
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.002
    technique_name: Create or Modify System Process
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://wiz.io/blog/mini-shai-hulud-teampcp-hits-antv-supply-chain
  - https://nrwl.io/nx/impact-report
iocs:
  - type: domain
    value: m-kosche.com
  - type: ip
    value: 185.95.159.32
  - type: hash_md5
    value: b06b126b9e26af03a7ef2f8b8e90d446
  - type: hash_sha256
    value: fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142
ioc_counts:
  domain: 1
  hash_md5: 1
  hash_sha256: 1
  ip: 1
rules:
  - title: Detect TeamPCP Backdoor Installation
    description: Detects the installation of the TeamPCP backdoor by monitoring file creation in the expected directory.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect TeamPCP Backdoor Polling for C2
    description: Detects TeamPCP backdoor polling GitHub for commands by monitoring network connections to api.github.com with the 'firedalazer' query.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect TeamPCP Exfiltration via GitHub Repository Description
    description: Detects TeamPCP exfiltration attempts by monitoring for unusual GitHub repository creation with a reversed description containing 'duluH-iahS'.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

On May 19, 2026, a software supply chain attack targeting the open-source ecosystem reemerged, affecting NPM packages, GitHub Actions, and VSCode extensions. The distributed malware, attributed to TeamPCP with moderate confidence, is designed to harvest credentials, exfiltrate sensitive data, and establish persistent access on infected systems. The attack specifically targets NPM packages within the @antv namespace, the GitHub Actions actions-cool/issues-helper, and the VSCode extension nrwl.angular-console v18.95.0. The attackers used orphaned GitHub commits to host payloads and the bun package manager to install secondary payloads. The malware then exfiltrates collected data through attacker-created public GitHub repositories.

## Attack Chain

1.  Malicious NPM packages, GitHub Actions, or VSCode extensions are installed on a developer's machine or CI/CD environment.
2.  The initial malicious code retrieves additional payloads from GitHub-hosted infrastructure, potentially stored in orphaned commits.
3.  The payloads are installed and executed using bun.
4.  The malware collects sensitive artifacts, including GitHub tokens, SSH keys, cloud credentials, and browser-stored secrets.
5.  The collected data is exfiltrated to attacker-controlled public GitHub repositories, with repositories created with the description `niagA oG eW ereH :duluH-iahS` (Shai-Hulud Here We Go Again).
6.  A Python-based backdoor is installed at `~/.local/share/kitty/cat.py` to establish persistence.
7.  The backdoor periodically polls `api.github.com/search/commits?q=firedalazer` for command-and-control messages containing the string `firedalazer`.
8.  Upon finding a valid signed instruction, the malware retrieves and executes remote Python code from attacker-controlled infrastructure, allowing remote execution.

## Impact

This supply chain attack can lead to the compromise of developer credentials, cloud resources, and sensitive data. Successful exploitation allows attackers to gain persistent access to infected systems and CI/CD pipelines, potentially leading to further supply chain compromises and data breaches. The compromise of developer credentials can lead to unauthorized access to source code repositories, build systems, and production environments. The number of victims and the full extent of the damage are still under investigation.

## Recommendation

*   Investigate developer workstations, CI/CD environments, and repositories for signs of compromise, auditing for the affected packages, GitHub Actions, and VSCode extensions listed in the appendix of this brief.
*   Rotate potentially exposed GitHub tokens, SSH keys, cloud credentials, and CI/CD secrets due to the malware's credential theft capabilities as described in the overview.
*   Hunt for persistence mechanisms, including the presence of the file `~/.local/share/kitty/cat.py`, as detailed in the "File Paths" IOC section.
*   Deploy the "Detect TeamPCP Backdoor Polling for C2" Sigma rule to identify systems polling GitHub for commands.
*   Block the C2 domain `m-kosche.com` at the DNS resolver to prevent command and control communication as listed in the IOC table.
