(() => {
  const body = document.body;
  const userId = body.dataset.userId || 'anon';
  const themeKey = `ebooks-theme-${userId}`;
  const navBtn = document.querySelector('[data-toggle-nav]');
  const nav = document.querySelector('[data-nav]');
  const tools = document.querySelector('[data-tools]');
  const themeButtons = [...document.querySelectorAll('[data-theme-toggle]')];
  const menuBtn = document.querySelector('[data-user-menu-trigger]');
  const dropdown = document.querySelector('[data-user-dropdown]');

  const saved = localStorage.getItem(themeKey);
  if (saved === 'dark') body.classList.add('dark');
  themeButtons.forEach((btn) => btn.setAttribute('aria-pressed', body.classList.contains('dark') ? 'true' : 'false'));

  navBtn?.addEventListener('click', () => {
    nav?.classList.toggle('open');
    tools?.classList.toggle('open');
  });

  const toggleTheme = () => {
    body.classList.toggle('dark');
    const isDark = body.classList.contains('dark');
    localStorage.setItem(themeKey, isDark ? 'dark' : 'light');
    themeButtons.forEach((btn) => btn.setAttribute('aria-pressed', isDark ? 'true' : 'false'));
  };
  themeButtons.forEach((btn) => btn.addEventListener('click', toggleTheme));

  menuBtn?.addEventListener('click', () => dropdown?.classList.toggle('open'));
  document.addEventListener('click', (e) => {
    if (!e.target.closest('[data-user-menu]')) dropdown?.classList.remove('open');
  });
})();

(() => {
  const slides = [...document.querySelectorAll('[data-hero-slide]')];
  const dotsWrap = document.querySelector('[data-hero-dots]');
  if (!slides.length || !dotsWrap) return;

  let idx = slides.findIndex((s) => s.classList.contains('active'));
  if (idx < 0) idx = 0;

  const dots = slides.map((_, i) => {
    const b = document.createElement('button');
    b.className = 'hero-dot' + (i === idx ? ' active' : '');
    b.type = 'button';
    b.addEventListener('click', () => show(i));
    dotsWrap.appendChild(b);
    return b;
  });

  function show(i) {
    idx = (i + slides.length) % slides.length;
    slides.forEach((s, n) => s.classList.toggle('active', n === idx));
    dots.forEach((d, n) => d.classList.toggle('active', n === idx));
  }

  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    setInterval(() => show(idx + 1), 5000);
  }
})();

(() => {
  const wrap = document.querySelector('[data-view-switch]');
  const results = document.querySelector('[data-catalog-results]');
  if (!wrap || !results) return;

  const key = `ebooks-catalog-view-${document.body.dataset.userId || 'anon'}`;
  const saved = localStorage.getItem(key);
  if (saved === 'list') {
    results.classList.remove('grid-view');
    results.classList.add('list-view');
    wrap.querySelector('[data-view="list"]')?.classList.add('active');
    wrap.querySelector('[data-view="grid"]')?.classList.remove('active');
  }

  wrap.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-view]');
    if (!btn) return;
    const mode = btn.dataset.view;
    results.classList.toggle('grid-view', mode === 'grid');
    results.classList.toggle('list-view', mode === 'list');
    wrap.querySelectorAll('button').forEach((b) => b.classList.toggle('active', b === btn));
    localStorage.setItem(key, mode);
  });
})();

(() => {
  const favBtn = document.querySelector('[data-fav-btn]');
  if (favBtn) {
    favBtn.addEventListener('click', async () => {
      const ebookId = favBtn.dataset.ebookId;
      const csrf = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value || '';
      const res = await fetch(`/ebooks/${ebookId}/favorite/`, { method: 'POST', headers: { 'X-CSRFToken': csrf } });
      if (!res.ok) return;
      const data = await res.json();
      favBtn.classList.toggle('active', data.favorited);
      favBtn.textContent = data.favorited ? '♥ Favorited' : '♡ Add to Favorites';
    });
  }

  const loadMore = document.querySelector('[data-load-more-reviews]');
  if (loadMore) {
    loadMore.addEventListener('click', () => {
      document.querySelectorAll('.hidden-review').forEach((el) => el.classList.remove('hidden-review'));
      loadMore.remove();
    });
  }

  const codeForm = document.querySelector('#codeValidateForm');
  if (codeForm) {
    const progressWrap = document.querySelector('.progress-wrap');
    const progress = document.querySelector('[data-progress]');
    const feedback = document.querySelector('[data-code-feedback]');
    const links = document.querySelector('[data-download-links]');
    const submit = codeForm.querySelector('[data-code-submit]') || codeForm.querySelector('button[type="submit"]');
    const captchaInput = codeForm.querySelector('[data-captcha-input]');
    const captchaPrompt = document.querySelector('[data-captcha-prompt]');

    codeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(codeForm);
      const csrf = codeForm.querySelector('input[name="csrfmiddlewaretoken"]')?.value || '';

      submit && (submit.disabled = true);
      progressWrap.hidden = false;
      progress.style.width = '20%';
      feedback.classList.remove('success', 'error');
      feedback.textContent = 'Validating code...';
      links.innerHTML = '';

      try {
        const res = await fetch('/ebooks/codes/validate/', { method: 'POST', body: formData, headers: { 'X-CSRFToken': csrf } });
        progress.style.width = '70%';
        const data = await res.json();
        if (!res.ok) {
          progress.style.width = '0%';
          feedback.classList.add('error');
          feedback.textContent = data.error || 'Code validation failed.';
          if (data.captcha_required && captchaInput && captchaPrompt) {
            captchaInput.hidden = false;
            captchaPrompt.hidden = false;
            captchaPrompt.textContent = `Captcha: ${data.captcha_prompt || 'Solve challenge'}`;
          }
          return;
        }

        progress.style.width = '100%';
        feedback.classList.add('success');
        feedback.textContent = data.message || 'Code accepted. Temporary links ready.';
        (data.files || []).forEach((f) => {
          const a = document.createElement('a');
          a.href = f.download_url || '#';
          a.textContent = `${f.name} (${f.version}) • ${f.size} bytes`;
          a.target = '_blank';
          links.appendChild(a);
        });
      } catch {
        progress.style.width = '0%';
        feedback.classList.add('error');
        feedback.textContent = 'Network error during validation. Please retry.';
      } finally {
        submit && (submit.disabled = false);
      }
    });
  }
})();

(() => {
  const tabWrap = document.querySelector('[data-profile-tabs]');
  if (!tabWrap) return;

  const tabButtons = [...tabWrap.querySelectorAll('[data-tab-target]')];
  const panels = [...document.querySelectorAll('[data-tab-panel]')];

  function activate(name) {
    tabButtons.forEach((btn) => btn.classList.toggle('active', btn.dataset.tabTarget === name));
    panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.tabPanel === name));
  }

  tabWrap.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-tab-target]');
    if (!btn) return;
    activate(btn.dataset.tabTarget);
  });

  const csrf = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value || '';

  document.querySelectorAll('[data-remove-favorite]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const ebookId = btn.dataset.removeFavorite;
      const res = await fetch(`/ebooks/${ebookId}/favorite/`, { method: 'POST', headers: { 'X-CSRFToken': csrf } });
      if (!res.ok) return;
      const data = await res.json();
      if (!data.favorited) {
        document.querySelector(`[data-favorite-card="${ebookId}"]`)?.remove();
      }
    });
  });

  document.querySelectorAll('[data-delete-review]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const reviewId = btn.dataset.deleteReview;
      const res = await fetch(`/ebooks/reviews/me/${reviewId}/delete/`, { method: 'POST', headers: { 'X-CSRFToken': csrf } });
      if (!res.ok) return;
      const data = await res.json();
      if (data.deleted) {
        document.querySelector(`[data-review-card="${reviewId}"]`)?.remove();
      }
    });
  });
})();

(() => {
  const adminRoot = document.querySelector('[data-admin-dashboard]');
  if (!adminRoot) return;

  const sidebar = document.querySelector('[data-admin-sidebar]');
  const sidebarBtn = document.querySelector('[data-admin-sidebar-toggle]');
  sidebarBtn?.addEventListener('click', () => sidebar?.classList.toggle('open'));

  const filterInput = document.querySelector('[data-admin-activity-filter]');
  const rows = [...document.querySelectorAll('[data-activity-row]')];
  filterInput?.addEventListener('input', () => {
    const q = filterInput.value.trim().toLowerCase();
    rows.forEach((row) => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  document.querySelectorAll('[data-chart-bars]').forEach((group) => {
    const bars = [...group.querySelectorAll('.chart-bar')];
    const max = Math.max(...bars.map((b) => Number(b.dataset.value || 0)), 1);
    bars.forEach((bar, idx) => {
      const value = Number(bar.dataset.value || 0);
      const target = Math.max(4, Math.round((value / max) * 100));
      setTimeout(() => {
        bar.style.width = `${target}%`;
      }, 80 * idx);
    });
  });
})();

(() => {
  const banner = document.querySelector('[data-dismissible-banner]');
  if (banner) {
    const key = `ebooks-dismissed-banner-${banner.dataset.dismissibleBanner}`;
    if (localStorage.getItem(key) === '1') {
      banner.remove();
    } else {
      banner.querySelector('[data-dismiss-banner]')?.addEventListener('click', () => {
        banner.classList.add('is-closing');
        localStorage.setItem(key, '1');
        setTimeout(() => banner.remove(), 220);
      });
    }
  }

  const toasts = [...document.querySelectorAll('[data-toast]')];
  toasts.forEach((toast) => {
    const dismiss = () => {
      toast.classList.add('is-closing');
      setTimeout(() => toast.remove(), 220);
    };
    toast.querySelector('[data-dismiss-toast]')?.addEventListener('click', dismiss);
    setTimeout(dismiss, 4500);
  });
})();


(() => {
  const topBtn = document.querySelector('[data-scroll-top]');
  if (!topBtn) return;

  const sync = () => {
    topBtn.classList.toggle('visible', window.scrollY > 240);
  };
  sync();
  window.addEventListener('scroll', sync, { passive: true });
  topBtn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
})();
