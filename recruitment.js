/* NZI — Recrutamento: validação e envio real da candidatura (POST /api/recruitment/apply).
   Nada é simulado: o "sucesso" só aparece depois que o servidor confirma que a candidatura foi recebida. */
(function () {
  'use strict';
  var form = document.getElementById('rc-form');
  if (!form) return;

  var $ = function (id) { return document.getElementById(id); };
  var nick = $('rc-nick');
  var count = $('rc-count');
  var nickErr = $('rc-nick-err');
  var reqErr = $('rc-req-err');
  var fieldset = $('rc-fieldset');
  var feedback = $('rc-feedback');
  var btn = $('rc-submit');
  var btnLabel = btn.querySelector('.rc-btn-label');
  var radios = Array.prototype.slice.call(form.querySelectorAll('input[name="requirement"]'));
  var NICK_MAX = parseInt(nick.getAttribute('maxlength'), 10) || 15;
  var NICK_RE = /^[\p{L}\p{N}_.\-\[\] ]+$/u;
  var sending = false;

  function len(s) { return Array.from(s).length; }

  /* ---------- contador do nick ---------- */
  function updateCount() {
    var n = len(nick.value);
    count.textContent = n + '/' + NICK_MAX;
    count.classList.toggle('is-max', n >= NICK_MAX);
  }
  nick.addEventListener('input', function () {
    updateCount();
    if (nick.getAttribute('aria-invalid') === 'true') validateNick();
  });
  nick.addEventListener('blur', function () { if (nick.value) validateNick(); });

  /* ---------- seleção única do requisito ---------- */
  function syncChecked() {
    radios.forEach(function (r) { r.parentNode.classList.toggle('is-checked', r.checked); });
  }
  radios.forEach(function (r) {
    r.addEventListener('change', function () { syncChecked(); setReqError(''); });
  });

  /* ---------- erros por campo ---------- */
  function setNickError(msg) {
    nickErr.textContent = msg || '';
    nickErr.hidden = !msg;
    if (msg) nick.setAttribute('aria-invalid', 'true'); else nick.removeAttribute('aria-invalid');
  }
  function setReqError(msg) {
    reqErr.textContent = msg || '';
    reqErr.hidden = !msg;
    fieldset.classList.toggle('is-invalid', !!msg);
  }
  function validateNick() {
    var v = nick.value.trim().replace(/\s+/g, ' ');
    if (!v) { setNickError('Informe o seu nick.'); return false; }
    if (len(v) > NICK_MAX) { setNickError('O nick deve ter no máximo ' + NICK_MAX + ' caracteres.'); return false; }
    if (!NICK_RE.test(v)) { setNickError('Use apenas letras, números, espaço e os símbolos _ . - [ ].'); return false; }
    setNickError('');
    return true;
  }
  function selected() {
    for (var i = 0; i < radios.length; i++) if (radios[i].checked) return radios[i];
    return null;
  }
  function validateReq() {
    if (!selected()) { setReqError('Escolha exatamente um requisito.'); return false; }
    setReqError('');
    return true;
  }

  /* ---------- feedback visual ---------- */
  function showFeedback(kind, title, text, action) {
    feedback.className = 'rc-feedback ' + (kind === 'ok' ? 'is-ok' : 'is-err');
    feedback.innerHTML = '';
    var s = document.createElement('strong'); s.textContent = title;
    var p = document.createElement('span'); p.textContent = text;
    feedback.appendChild(s); feedback.appendChild(p);
    if (action && action.href) {
      var a = document.createElement('a');
      a.className = 'rc-root-btn';
      a.href = action.href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = action.label;
      feedback.appendChild(a);
    }
    feedback.hidden = false;
    // reinicia a animação mesmo em mensagens seguidas
    feedback.style.animation = 'none'; void feedback.offsetWidth; feedback.style.animation = '';
  }
  /* Botão pós-envio: o link vem de data-root-url no <form id="rc-form"> (editável no HTML).
     Só aceita http(s) para nunca montar um link javascript:. */
  function rootLink() {
    var url = form.getAttribute('data-root-url') || '';
    if (!/^https:\/\//i.test(url)) return null;
    return { href: url, label: form.getAttribute('data-root-label') || 'Aguarde seu recrutamento no Root' };
  }
  function hideFeedback() { feedback.hidden = true; feedback.textContent = ''; }

  function setBusy(on) {
    sending = on;
    btn.disabled = on;
    if (on) btn.setAttribute('aria-busy', 'true'); else btn.removeAttribute('aria-busy');
    btnLabel.textContent = on ? 'Enviando…' : 'Enviar candidatura';
  }

  /* ---------- envio ---------- */
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (sending) return;
    hideFeedback();

    var okNick = validateNick();
    var okReq = validateReq();
    if (!okNick || !okReq) {
      showFeedback('err', 'Revise o formulário', 'Preencha o nick (até ' + NICK_MAX + ' caracteres) e escolha um requisito antes de enviar.');
      (okNick ? radios[0] : nick).focus();
      return;
    }

    var r = selected();
    var txtEl = r.parentNode.querySelector('.rc-txt');
    var payload = {
      nick: nick.value.trim().replace(/\s+/g, ' '),
      requirement: parseInt(r.value, 10),
      requirementText: txtEl ? txtEl.textContent.trim() : '',
      website: form.elements.website ? form.elements.website.value : ''
    };

    setBusy(true);
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 15000) : null;

    fetch('/api/recruitment/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (d) { return { res: res, d: d || {} }; });
    }).then(function (x) {
      var d = x.d;
      if (x.res.ok && d.success) {
        var who = payload.nick;
        form.reset();
        syncChecked(); updateCount(); setNickError(''); setReqError('');
        showFeedback('ok', 'Candidatura enviada!',
          'Recebemos a candidatura de "' + who + '"' + (d.protocol ? ' (protocolo #' + d.protocol + ')' : '') +
          '. A equipe da NZI vai analisar e entrar em contato.',
          rootLink());
        return;
      }
      if (d.fields) {
        if (d.fields.nick) setNickError(d.fields.nick);
        if (d.fields.requirement) setReqError(d.fields.requirement);
      }
      showFeedback('err', 'Não foi possível enviar', d.error || 'Erro ao enviar a candidatura. Tente novamente.');
    }).catch(function (err) {
      var timeout = err && err.name === 'AbortError';
      showFeedback('err', 'Não foi possível enviar',
        timeout ? 'O servidor demorou para responder. Tente novamente.' : 'Servidor indisponível ou erro de rede. Tente de novo.');
    }).then(function () {
      if (timer) clearTimeout(timer);
      setBusy(false);
    });
  });

  updateCount();
  syncChecked();
})();
