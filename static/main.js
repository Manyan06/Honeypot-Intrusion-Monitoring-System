/* ── Matrix Rain ──────────────────────────────────────── */
const canvas = document.getElementById("matrix");
const ctx    = canvas.getContext("2d");

function resize() {
  canvas.width  = window.innerWidth;
  canvas.height = window.innerHeight;
}
resize();
window.addEventListener("resize", resize);

const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモ";
const fontSize = 13;
let columns = Math.floor(canvas.width / fontSize);
let drops   = Array(columns).fill(1);

function drawMatrix() {
  ctx.fillStyle = "rgba(5, 13, 20, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#00ff88";
  ctx.font      = `${fontSize}px 'Share Tech Mono', monospace`;

  for (let i = 0; i < drops.length; i++) {
    const ch = chars[Math.floor(Math.random() * chars.length)];
    ctx.fillText(ch, i * fontSize, drops[i] * fontSize);
    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
      drops[i] = 0;
    }
    drops[i]++;
  }
}

setInterval(drawMatrix, 60);

/* ── Live Clock ───────────────────────────────────────── */
function updateClock() {
  const el = document.getElementById("clock");
  if (!el) return;
  const now = new Date();
  el.textContent =
    now.toISOString().slice(0, 10) + " " +
    now.toTimeString().slice(0, 8) + " UTC";
}
updateClock();
setInterval(updateClock, 1000);