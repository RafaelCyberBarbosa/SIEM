// Minimal dependency-free canvas charts.

function drawBarChart(canvas, labels, values, color = "#2ee6d6") {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const max = Math.max(1, ...values);
  const padLeft = 34, padBottom = 20, padTop = 10, padRight = 6;
  const chartW = w - padLeft - padRight;
  const chartH = h - padBottom - padTop;
  const barGap = 4;
  const barW = Math.max(2, chartW / values.length - barGap);

  ctx.strokeStyle = "rgba(76,236,210,0.15)";
  ctx.beginPath();
  ctx.moveTo(padLeft, padTop);
  ctx.lineTo(padLeft, h - padBottom);
  ctx.lineTo(w - padRight, h - padBottom);
  ctx.stroke();

  ctx.fillStyle = "#5f7891";
  ctx.font = "10px 'JetBrains Mono', monospace";
  ctx.fillText(String(max), 2, padTop + 8);
  ctx.fillText("0", 2, h - padBottom);

  const grad = ctx.createLinearGradient(0, h - padBottom, 0, padTop);
  grad.addColorStop(0, color);
  grad.addColorStop(1, "#3ea6ff");

  values.forEach((v, i) => {
    const x = padLeft + i * (barW + barGap);
    const barH = (v / max) * chartH;
    const y = h - padBottom - barH;
    ctx.save();
    if (v > 0) {
      ctx.shadowColor = color;
      ctx.shadowBlur = 2;
    }
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, barW, barH);
    ctx.restore();
  });

  ctx.fillStyle = "#5f7891";
  ctx.font = "9px 'JetBrains Mono', monospace";
  const step = Math.max(1, Math.floor(labels.length / 8));
  labels.forEach((l, i) => {
    if (i % step !== 0) return;
    const x = padLeft + i * (barW + barGap);
    ctx.fillText(l, x, h - 4);
  });
}

function drawDonutChart(canvas, dataObj, colorMap) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const entries = Object.entries(dataObj).filter(([, v]) => v > 0);
  const total = entries.reduce((a, [, v]) => a + v, 0);
  const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 6, inner = r * 0.6;

  if (total === 0) {
    ctx.strokeStyle = "rgba(76,236,210,0.2)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(cx, cy, (r + inner) / 2, 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = "#5f7891";
    ctx.font = "11px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    ctx.fillText("SEM ALERTAS", cx, cy);
    ctx.textAlign = "left";
    return;
  }

  let start = -Math.PI / 2;
  entries.forEach(([key, val]) => {
    const angle = (val / total) * Math.PI * 2;
    ctx.save();
    ctx.shadowColor = colorMap[key] || "#3ea6ff";
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = colorMap[key] || "#3ea6ff";
    ctx.fill();
    ctx.restore();
    start += angle;
  });

  ctx.globalCompositeOperation = "destination-out";
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalCompositeOperation = "source-over";

  ctx.fillStyle = "#dbe9f5";
  ctx.font = "bold 17px 'Orbitron', sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(String(total), cx, cy + 6);
  ctx.textAlign = "left";
}

const SEVERITY_COLORS = {
  info: "#60a5fa", low: "#34d399", medium: "#fbbf24", high: "#fb923c", critical: "#ef4444",
};
