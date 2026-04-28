---
title: "Subscribe"
description: "Get filtered alerts when matching briefs land — by email, Slack, or Microsoft Teams."
layout: subscribe
---

## Subscribe to alerts

Pick a delivery channel and the filters you care about. We'll send a notification when a brief matches every filter you've selected.

The simplest case — get every critical threat — is two clicks. Beyond that, every filter narrows the feed (filters AND across categories, OR within each).

<form id="subscribe-form" class="space-y-6 my-8 not-prose">

  <fieldset class="rounded-xl border border-stroke bg-panel/60 p-5 space-y-3">
    <legend class="text-xs font-mono uppercase tracking-[0.14em] text-muted px-2">Channel</legend>
    <div class="flex flex-wrap gap-3 text-sm">
      <label class="inline-flex items-center gap-2 cursor-pointer">
        <input type="radio" name="channel" value="email" checked class="accent-accent">
        Email
      </label>
      <label class="inline-flex items-center gap-2 cursor-pointer">
        <input type="radio" name="channel" value="slack" class="accent-accent">
        Slack (incoming webhook)
      </label>
      <label class="inline-flex items-center gap-2 cursor-pointer">
        <input type="radio" name="channel" value="teams" class="accent-accent">
        Microsoft Teams (incoming webhook)
      </label>
    </div>

    <div data-channel-fields="email" class="space-y-1">
      <label for="sub-email" class="text-xs uppercase tracking-wider text-muted">Email address</label>
      <input id="sub-email" name="email" type="email" required class="w-full rounded-lg border border-stroke bg-panel-2 px-3 py-2 text-sm font-mono focus:outline-none focus:border-accent" placeholder="you@example.com">
    </div>

    <div data-channel-fields="slack teams" class="space-y-1 hidden">
      <label for="sub-webhook" class="text-xs uppercase tracking-wider text-muted">Webhook URL</label>
      <input id="sub-webhook" name="webhook_url" type="url" class="w-full rounded-lg border border-stroke bg-panel-2 px-3 py-2 text-sm font-mono focus:outline-none focus:border-accent" placeholder="https://hooks.slack.com/services/… or https://….webhook.office.com/…">
      <p class="text-xs text-muted">Create one in your workspace; we don't see anything beyond what you post to it.</p>
    </div>
  </fieldset>

  <fieldset class="rounded-xl border border-stroke bg-panel/60 p-5 space-y-4">
    <legend class="text-xs font-mono uppercase tracking-[0.14em] text-muted px-2">Filters</legend>

    <div class="space-y-2">
      <p class="text-xs uppercase tracking-wider text-muted">Type</p>
      <div class="flex flex-wrap gap-3 text-sm">
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="types" value="threat" class="accent-accent"> threat</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="types" value="coverage" class="accent-accent"> coverage</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="types" value="advisory" class="accent-accent"> advisory</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="types" value="rumour" class="accent-accent"> rumour</label>
      </div>
    </div>

    <div class="space-y-2">
      <p class="text-xs uppercase tracking-wider text-muted">Severity</p>
      <div class="flex flex-wrap gap-3 text-sm">
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="severities" value="critical" class="accent-accent"> critical</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="severities" value="high" class="accent-accent"> high</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="severities" value="medium" class="accent-accent"> medium</label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" name="severities" value="low" class="accent-accent"> low</label>
      </div>
    </div>

    <div class="space-y-2">
      <p class="text-xs uppercase tracking-wider text-muted">Other (comma-separated, exact match)</p>
      <div class="grid sm:grid-cols-3 gap-2 text-sm">
        <input name="products" type="text" class="rounded-lg border border-stroke bg-panel-2 px-3 py-2 font-mono focus:outline-none focus:border-accent" placeholder="products: FortiGate, Citrix">
        <input name="actors" type="text" class="rounded-lg border border-stroke bg-panel-2 px-3 py-2 font-mono focus:outline-none focus:border-accent" placeholder="actors: APT29, Volt Typhoon">
        <input name="tags" type="text" class="rounded-lg border border-stroke bg-panel-2 px-3 py-2 font-mono focus:outline-none focus:border-accent" placeholder="tags: edge-device">
      </div>
    </div>

    <label class="inline-flex items-center gap-2 text-sm">
      <input type="checkbox" name="exploited" value="1" class="accent-accent">
      Only when exploited in the wild
    </label>
  </fieldset>

  <div class="flex items-center gap-4">
    <button type="submit" class="px-4 py-2 rounded-xl bg-accent text-white text-sm font-semibold shadow-soft hover:scale-[1.01] transition disabled:opacity-50 disabled:cursor-not-allowed">
      Subscribe
    </button>
    <p data-subscribe-status class="text-sm" role="status" aria-live="polite"></p>
  </div>
</form>

## Pre-baked feeds (no signup)

If you don't need compound filters, every taxonomy term has its own RSS feed:

- **All briefs** — `/feed.xml`
- **By severity** — `/severities/critical/feed.xml`, `/severities/high/feed.xml`, …
- **By type** — `/types/threat/feed.xml`, `/types/coverage/feed.xml`, …
- **By product** — `/products/<slug>/feed.xml`
- **By actor** — `/actors/<slug>/feed.xml`
- **By tag** — `/tags/<slug>/feed.xml`

Slack supports RSS natively (`/feed subscribe <url>`). Teams has an "RSS" connector. For email, paste an RSS URL into Buttondown, Feedrabbit, or Follow.it.
