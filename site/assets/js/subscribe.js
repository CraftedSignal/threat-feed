// Subscribe form handler. Toggles channel-specific inputs, gets a
// reCAPTCHA Enterprise score token at submit time, and POSTs to the
// notifier service. Cloud Armor blocks submissions without a valid
// token, so we *must* include it.

(function () {
  const form = document.getElementById('subscribe-form');
  if (!form) return;

  const notifierURL = form.dataset.notifierUrl;
  const recaptchaKey = form.dataset.recaptchaKey;
  const status = form.querySelector('[data-subscribe-status]');
  const submitBtn = form.querySelector('button[type="submit"]');

  // Toggle visibility of email vs webhook inputs based on selected channel.
  function applyChannel() {
    const channel = form.querySelector('input[name="channel"]:checked')?.value || 'email';
    form.querySelectorAll('[data-channel-fields]').forEach((el) => {
      const matches = el.dataset.channelFields.split(' ').includes(channel);
      el.classList.toggle('hidden', !matches);
      el.querySelectorAll('input').forEach((i) => {
        i.required = matches;
        i.disabled = !matches;
      });
    });
  }
  form.querySelectorAll('input[name="channel"]').forEach((r) => r.addEventListener('change', applyChannel));
  applyChannel();

  function setStatus(msg, kind) {
    if (!status) return;
    status.textContent = msg;
    status.className = 'text-sm';
    if (kind === 'error') status.classList.add('text-sev-critical');
    else if (kind === 'success') status.classList.add('text-sev-low');
    else status.classList.add('text-muted');
  }

  function listFromCSV(value) {
    return (value || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function getRecaptchaToken(action) {
    if (!recaptchaKey || !window.grecaptcha?.enterprise) return '';
    return new Promise((resolve, reject) => {
      window.grecaptcha.enterprise.ready(async () => {
        try {
          const token = await window.grecaptcha.enterprise.execute(recaptchaKey, { action });
          resolve(token);
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!notifierURL) {
      setStatus('Notifier URL is not configured. Tell the operator to set notifierURL in hugo.toml.', 'error');
      return;
    }

    submitBtn.disabled = true;
    setStatus('Submitting…');

    const data = new FormData(form);
    const channel = data.get('channel');
    const filter = {
      types: data.getAll('types'),
      severities: data.getAll('severities'),
      actors: listFromCSV(data.get('actors')),
      vendors: listFromCSV(data.get('vendors')),
      products: listFromCSV(data.get('products')),
      tags: listFromCSV(data.get('tags')),
      exploited: data.get('exploited') === '1',
      include_updates: data.get('include_updates') === '1',
    };
    const body = {
      channel,
      filter,
    };
    if (channel === 'email') body.email = data.get('email');
    else body.webhook_url = data.get('webhook_url');

    let token = '';
    try {
      token = await getRecaptchaToken('subscribe');
    } catch (err) {
      console.error('recaptcha failed', err);
    }

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['X-Recaptcha-Token'] = token;
      const res = await fetch(notifierURL + '/subscribe', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        credentials: 'omit',
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        throw new Error(`HTTP ${res.status}: ${txt || 'submission failed'}`);
      }
      if (channel === 'email') {
        setStatus('Check your inbox to confirm.', 'success');
        form.reset();
        applyChannel();
      } else {
        setStatus('Subscription active — webhooks are confirmed by URL possession.', 'success');
        form.reset();
        applyChannel();
      }
    } catch (err) {
      console.error(err);
      setStatus(err.message || 'Submission failed.', 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });
})();
