/* ==========================================================================
   Allsafe Client Portal — form controller
   --------------------------------------------------------------------------
   Transport only. Reads window.AllsafePortalAuth for the endpoint and options,
   posts the credential pair, renders the verdict. Contains no knowledge of the
   authentication mechanism behind the endpoint.
   ========================================================================== */
(function () {
  'use strict';

  var cfg = window.AllsafePortalAuth || {};
  var form = document.getElementById('portal-login');
  var out = document.getElementById('pf-result');
  var button = document.getElementById('pf-submit');
  if (!form || !out || !button) { return; }

  /* ---- Verdict rendering ------------------------------------------------ */
  function render(kind, heading, detail) {
    out.hidden = false;
    out.className = 'portal-result portal-result--' + kind;
    out.innerHTML = '';
    var strong = document.createElement('strong');
    strong.textContent = heading;
    out.appendChild(strong);
    // textContent, not innerHTML — the endpoint's message is untrusted input
    out.appendChild(document.createTextNode(detail || ''));
  }

  function busy(state) {
    button.disabled = state;
    button.textContent = state ? 'Checking…' : 'Sign in';
  }

  /* ---- Submit ----------------------------------------------------------- */
  form.addEventListener('submit', function (e) {
    e.preventDefault();

    var username = form.username.value.trim();
    var password = form.password.value;

    if (!username || !password) {
      render('denied', 'Missing details.', ' Enter both a username and a password.');
      return;
    }

    busy(true);

    // AbortController keeps an unreachable directory from hanging the form.
    var controller = ('AbortController' in window) ? new AbortController() : null;
    var timer = controller ? window.setTimeout(function () { controller.abort(); }, cfg.timeoutMs || 8000) : null;

    fetch(cfg.endpoint || '/portal/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: cfg.withCredentials ? 'same-origin' : 'omit',
      body: JSON.stringify({ username: username, password: password }),
      signal: controller ? controller.signal : undefined
    })
      .then(function (res) {
        // Parse JSON when offered; otherwise fall back to the HTTP status so a
        // plain mod_authnz_ldap-protected path still works unmodified.
        return res.text().then(function (text) {
          var body = null;
          try { body = JSON.parse(text); } catch (err) { /* not JSON — fine */ }
          return { ok: res.ok, status: res.status, body: body };
        });
      })
      .then(function (res) {
        var verdict = res.body && res.body.status;
        if (!verdict) {
          verdict = res.ok ? 'granted' : (res.status === 401 || res.status === 403 ? 'denied' : 'error');
        }

        if (verdict === 'granted') {
          render('granted', 'Access granted.',
            ' ' + ((res.body && res.body.message) || 'Signed in. Loading your workspace…'));
          form.password.value = '';
          var target = (res.body && res.body.redirect) || cfg.successRedirect;
          if (target) { window.setTimeout(function () { window.location.assign(target); }, 900); }
        } else if (verdict === 'denied') {
          render('denied', 'Access denied.',
            ' ' + ((res.body && res.body.message) || 'Those credentials were not accepted.'));
          form.password.value = '';
          form.password.focus();
        } else {
          render('error', 'Sign-in unavailable.',
            ' ' + ((res.body && res.body.message) || cfg.errorMessage));
        }
      })
      .catch(function () {
        render('error', 'Sign-in unavailable.', ' ' + (cfg.errorMessage || 'The sign-in service is not responding.'));
      })
      .then(function () {
        if (timer) { window.clearTimeout(timer); }
        busy(false);
      });
  });
})();
