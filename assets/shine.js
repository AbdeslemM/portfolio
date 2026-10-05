/* ═══════════════════════════════════════════
   SHINE — progressive enhancements (visual only)
   Every effect leaves the original text in place when it finishes,
   and nothing runs when the user prefers reduced motion.
═══════════════════════════════════════════ */
(() => {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  /* ─── Typing animation on the role line ─────────── */
  const tag = document.querySelector('.hero-tag');
  if (tag) {
    const full = tag.textContent;
    const caret = document.createElement('span');
    caret.className = 'type-caret';
    caret.setAttribute('aria-hidden', 'true');

    if (reduce) {
      tag.appendChild(caret);
    } else {
      tag.appendChild(caret);
      // Lock the pill's final size so typing doesn't shift the layout
      tag.style.minWidth = `${Math.ceil(tag.getBoundingClientRect().width)}px`;

      const sr = document.createElement('span');
      sr.className = 'sr-only';
      sr.textContent = full;
      const typed = document.createElement('span');
      typed.setAttribute('aria-hidden', 'true');
      tag.textContent = '';
      tag.append(sr, typed, caret);

      let i = 0;
      const step = () => {
        typed.textContent = full.slice(0, ++i);
        if (i < full.length) setTimeout(step, 38 + Math.random() * 40);
        else {
          // Restore a single plain text node: identical text to the original
          tag.textContent = full;
          tag.appendChild(caret);
        }
      };
      setTimeout(step, 550);
    }
  }

  /* ─── Rank numbers: animate the digits, end on the exact original text ── */
  const ranks = [...document.querySelectorAll('.achiev-rank')];
  if (!reduce && 'IntersectionObserver' in window) {
    const ease = t => 1 - Math.pow(1 - t, 3);
    ranks.forEach(el => {
      const original = el.textContent;
      const m = original.match(/\d+/);
      if (!m) return;
      const target = parseInt(m[0], 10);
      // Ranks "climb" toward their final value; larger targets count up from 0
      const from = target <= 1 ? 64 : 0;
      el.textContent = original.replace(/\d+/, String(from));

      const io = new IntersectionObserver(entries => {
        if (!entries.some(e => e.isIntersecting)) return;
        io.disconnect();
        const dur = 1400, t0 = performance.now() + 250;
        const tick = now => {
          const t = Math.min(Math.max((now - t0) / dur, 0), 1);
          const v = Math.round(from + (target - from) * ease(t));
          el.textContent = original.replace(/\d+/, String(v));
          if (t < 1) requestAnimationFrame(tick);
          else el.textContent = original;
        };
        requestAnimationFrame(tick);
      }, { threshold: 0.4 });
      io.observe(el);
    });
  }

  /* ─── 3D tilt on achievement cards (desktop pointers only) ── */
  if (!reduce && finePointer) {
    document.querySelectorAll('.achiev-card').forEach(card => {
      let raf = 0;
      card.addEventListener('pointermove', e => {
        const r = card.getBoundingClientRect();
        const px = (e.clientX - r.left) / r.width - 0.5;
        const py = (e.clientY - r.top) / r.height - 0.5;
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          card.classList.add('tilting');
          card.style.setProperty('--rx', `${(-py * 9).toFixed(2)}deg`);
          card.style.setProperty('--ry', `${(px * 11).toFixed(2)}deg`);
        });
      });
      card.addEventListener('pointerleave', () => {
        cancelAnimationFrame(raf);
        card.classList.remove('tilting');
        card.style.setProperty('--rx', '0deg');
        card.style.setProperty('--ry', '0deg');
      });
    });
  }
})();
