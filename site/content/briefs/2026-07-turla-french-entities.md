---
title: Targeting and Compromise of French Entities using the Turla Attack Method
slug: 2026-07-turla-french-entities
description: The Turla APT group, attributed to the 16th Center of Russia's Federal Security Service (FSB), has been observed targeting and compromising French entities since at least 2004 for intelligence gathering, impacting ministries and organizations in diplomatic, defense, justice, and technology sectors, with ongoing campaigns against NATO and EU countries.
date: "2026-07-13T09:24:23Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Turla
  - Snake
  - Venomous Bear
  - Secret Blizzard
  - Iron Hunter
tags:
  - espionage
  - state-sponsored
  - Turla
  - France
  - intelligence-gathering
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: à des fins de collecte de renseignement contre des entités stratégiques
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/cti/CERTFR-2026-CTI-004/
---

The French national cybersecurity agency (ANSSI) CERT-FR has observed state-sponsored cyber espionage activities attributed to the Turla APT group, operated by the 16th Center of Russia's Federal Security Service (FSB). Since at least 2004, Turla has been targeting and compromising strategic French entities and individuals for intelligence gathering, with a focus on ministries and organizations within the diplomatic, defense, justice, and technology sectors. These operations are part of ongoing campaigns targeting Ukraine, NATO member states, and European Union countries, continuing in the context of Russia's aggression against Ukraine. On July 13, 2026, France's Minister for Europe and Foreign Affairs, and the EU's High Representative for Foreign Affairs and Security Policy, formally attributed these malicious cyber activities to the FSB's 16th Center against France and its European partners. This threat emphasizes the persistent and long-term espionage efforts against critical national interests.

## Impact

Turla's long-standing intelligence gathering campaigns have led to the compromise of strategic French entities, including ministries and organizations in the diplomatic, defense, justice, and technology sectors. These operations extend globally, specifically targeting Ukraine, NATO, and EU member countries. The success of such attacks allows the Russian FSB to acquire sensitive information, impacting national security and foreign policy. The formal attribution by both France and the EU underscores the severity and the high-level nature of this state-sponsored espionage.

## Recommendation

Due to the high-confidence attribution to the Turla threat actor and the ongoing nature of their intelligence gathering operations, organizations should review their defenses against known Turla TTPs. Ensure enhanced monitoring and logging for anomalous activity, especially within critical ministries and entities in the diplomatic, defense, justice, and technology sectors.
