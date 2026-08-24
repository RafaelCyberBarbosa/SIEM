// Ambient "network map" particle background for the login screen.
// Lightweight, dependency-free, pauses automatically once the login screen is hidden.
(function () {
  const canvas = document.getElementById("bg-fx");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let w, h, particles, raf;
  const COLOR = "37, 244, 200"; // cyan accent, rgb triplet
  const COUNT_DIVISOR = 16000; // lower = more particles

  function resize() {
    w = canvas.width = canvas.offsetWidth * devicePixelRatio;
    h = canvas.height = canvas.offsetHeight * devicePixelRatio;
  }

  function init() {
    resize();
    const count = Math.min(90, Math.floor((w * h) / (COUNT_DIVISOR * devicePixelRatio * devicePixelRatio)));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: Math.random() * 1.6 + 0.6,
    }));
  }

  function step() {
    ctx.clearRect(0, 0, w, h);
    const linkDist = Math.min(w, h) * 0.16;

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
    }

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < linkDist) {
          ctx.strokeStyle = `rgba(${COLOR}, ${0.14 * (1 - dist / linkDist)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const p of particles) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * devicePixelRatio, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${COLOR}, 0.55)`;
      ctx.fill();
    }

    raf = requestAnimationFrame(step);
  }

  function isVisible() {
    const screen = document.getElementById("login-screen");
    return screen && !screen.classList.contains("hidden");
  }

  window.addEventListener("resize", () => { if (isVisible()) init(); });
  init();
  raf = requestAnimationFrame(function watch() {
    if (isVisible()) step();
    else raf = requestAnimationFrame(watch);
  });
})();

// Digital rain ("matrix") ambient backdrop for the main app shell.
// Very low opacity by design - it's texture, not a focal point. Pauses when the
// app is hidden (login screen) or the tab isn't visible, to keep CPU usage near zero.
(function () {
  const canvas = document.getElementById("app-bg-fx");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const GLYPHS = "01アイウエオカキクケコサシスセソタチツテト<>[]{}/\\;:#$%&SIEM0xDEADBEEF";
  const FONT_SIZE = 15;

  let w, h, cols, drops;

  function resize() {
    w = canvas.width = canvas.offsetWidth;
    h = canvas.height = canvas.offsetHeight;
    cols = Math.floor(w / FONT_SIZE);
    drops = Array.from({ length: cols }, () => Math.floor((Math.random() * h) / FONT_SIZE) * -1);
  }

  function isVisible() {
    const app = document.getElementById("app");
    return app && !app.classList.contains("hidden") && document.visibilityState === "visible";
  }

  function step() {
    ctx.fillStyle = "rgba(3, 6, 10, 0.14)";
    ctx.fillRect(0, 0, w, h);
    ctx.font = FONT_SIZE + "px 'JetBrains Mono', monospace";
    for (let i = 0; i < cols; i++) {
      const glyph = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
      const y = drops[i] * FONT_SIZE;
      ctx.fillStyle = y < FONT_SIZE * 2 ? "rgba(180, 255, 235, 0.5)" : "rgba(46, 230, 214, 0.28)";
      ctx.fillText(glyph, i * FONT_SIZE, y);
      if (y > h && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
    setTimeout(() => requestAnimationFrame(watch), 55);
  }

  function watch() {
    if (isVisible()) step();
    else requestAnimationFrame(watch);
  }

  window.addEventListener("resize", () => { if (isVisible()) resize(); });
  resize();
  requestAnimationFrame(watch);
})();
