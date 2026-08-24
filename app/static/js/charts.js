// Minimal dependency-free canvas charts.

function drawBarChart(canvas, labels, values, color = "#3ea6ff") {
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

  ctx.strokeStyle = "#232d3a";
  ctx.beginPath();
  ctx.moveTo(padLeft, padTop);
  ctx.lineTo(padLeft, h - padBottom);
  ctx.lineTo(w - padRight, h - padBottom);
  ctx.stroke();

  ctx.fillStyle = "#7c8ba1";
  ctx.font = "10px sans-serif";
  ctx.fillText(String(max), 2, padTop + 8);
  ctx.fillText("0", 2, h - padBottom);

  values.forEach((v, i) => {
    const x = padLeft + i * (barW + barGap);
    const barH = (v / max) * chartH;
    const y = h - padBottom - barH;
    ctx.fillStyle = color;
    ctx.fillRect(x, y, barW, barH);
  });

  ctx.fillStyle = "#7c8ba1";
  ctx.font = "9px sans-serif";
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
    ctx.fillStyle = "#7c8ba1";
    ctx.font = "12px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Sem alertas abertos", cx, cy);
    ctx.textAlign = "left";
    return;
  }

  let start = -Math.PI / 2;
  entries.forEach(([key, val]) => {
    const angle = (val / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = colorMap[key] || "#3ea6ff";
    ctx.fill();
    start += angle;
  });

  ctx.globalCompositeOperation = "destination-out";
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalCompositeOperation = "source-over";

  ctx.fillStyle = "#d7e0ea";
  ctx.font = "bold 16px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(String(total), cx, cy + 5);
  ctx.textAlign = "left";
}

const SEVERITY_COLORS = {
  info: "#3ea6ff", low: "#37d67a", medium: "#f2c94c", high: "#f2994a", critical: "#ff3b6b",
};
