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
