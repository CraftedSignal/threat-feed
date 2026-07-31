---
title: Pterodactyl Wings Configuration Secret Exposure via Egg Templating
slug: 2026-07-wings-secret-exposure
description: The Pterodactyl Wings daemon improperly exposes its full configuration to the egg templating engine, allowing low-privileged users to exfiltrate sensitive node secrets, including daemon tokens and registry credentials, via crafted configuration placeholders.
date: "2026-07-31T19:20:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - authentication-bypass
  - pterodactyl
  - wings
vendors:
  - Pterodactyl
products:
  - Wings (< 1.12.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Wings exposes its entire daemon configuration to the egg configuration-file templating engine.
    confidence_band: high
cves:
  - id: CVE-2026-52855
    cvss: 9.9
references:
  - https://github.com/advisories/GHSA-pfvc-3p5h-x7h6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-52855
---

Pterodactyl Wings versions prior to 1.12.3 contain a critical security vulnerability (CVE-2026-52855) where the daemon configuration is exposed to the egg configuration-file templating engine. Attackers with low-privileged access - such as server owners or subusers with `startup.update` permissions - can inject `{{config.*}}` placeholders into user-editable egg variables. When Wings renders these variables into server configuration files, it resolves the placeholders against the full daemon configuration, effectively disclosing sensitive credentials.

Impacted data includes the node's daemon token (used for Panel-to-Wings communication and JWT signing) and container registry credentials. Disclosure of the daemon token grants an attacker the ability to forge authentication tokens and execute commands across all servers hosted on the compromised node, leading to a complete node takeover. This vulnerability is prevalent in multi-tenant environments using stock or community-provided eggs that allow the rendering of user-controlled variables into configuration files.

## Attack Chain

1. Attacker authenticates to the Pterodactyl Panel using a low-privileged account (e.g., server owner or subuser with `startup.update` rights).
2. Attacker identifies an egg configuration in use that renders a user-editable variable into a server configuration file via `{{server.build.env.*}}`.
3. Attacker modifies the specific user-editable variable in the Panel, injecting a `{{config.token}}` or `{{config.docker.registries}}` placeholder.
4. The Panel accepts the malicious input and transmits the egg configuration containing the placeholder to the Wings daemon.
5. Wings processes the template and resolves the `{{config.token}}` placeholder against the internal daemon configuration.
6. Wings writes the resolved, sensitive credential into the target configuration file located within the server's directory.
7. Attacker accesses the server file via the built-in File Manager or SFTP to read the exfiltrated sensitive data.
8. Attacker leverages the stolen daemon token to forge authentication tokens, achieving full node compromise and administrative control over all hosted server instances.

## Impact

The vulnerability results in the full exposure of node-level credentials, including the daemon token and registry secrets. Successful exploitation allows a low-privileged attacker to achieve full node compromise. This affects any multi-tenant environment using Pterodactyl, where unauthorized parties can read data belonging to other users or the host system itself. Admins must upgrade Wings to v1.12.3 and rotate all node tokens to remediate the exposure.

## Recommendation

- Upgrade Pterodactyl Wings to version 1.12.3 or later immediately to restrict the configuration data accessible to the templating engine.
- After upgrading, rotate all affected node daemon tokens via the Admin interface (Nodes > Configuration > Reset Token) and trigger a re-deployment of the `config.yml` file.
- Audit all active eggs for user-editable variables that are rendered into configuration files; set these variables to non-editable if they are not strictly required by the server owner.
- Implement monitoring for unusual changes to startup parameters or environment variables in Pterodactyl logs, specifically looking for placeholders like `{{config.` as an indicator of attempted exploitation.
