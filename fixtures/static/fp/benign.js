// Usos legítimos de canvas: NO deben quedar como fingerprinting.
(function () {
  // 1. Gráfico de barras con varios colores y etiquetas, sin leer el canvas.
  var chart = document.getElementById('chart').getContext('2d');
  var colors = ['#4e79a7', '#f28e2b', '#e15759', '#76b7b2'];
  for (var i = 0; i < colors.length; i++) {
    chart.fillStyle = colors[i];
    chart.fillRect(20 + i * 60, 120 - (i + 1) * 20, 40, (i + 1) * 20);
    chart.fillText('Q' + (i + 1), 30 + i * 60, 140);
  }

  // 2. Animación: lee un píxel (1x1) en cada frame durante 5 s.
  var probe = document.createElement('canvas');
  probe.width = 1; probe.height = 1;
  var ctx = probe.getContext('2d', {willReadFrequently: true});
  var started = performance.now(), lastBeat = started, frames = 0;
  function tick(now) {
    ctx.fillStyle = 'rgb(' + (frames % 255) + ',0,0)';
    ctx.fillRect(0, 0, 1, 1);
    ctx.getImageData(0, 0, 1, 1);
    frames++;
    // Un latido por segundo mantiene vivo el scan (que termina tras 3 s sin requests) hasta el final.
    if (now - lastBeat >= 1000) { lastBeat = now; fetch('/fp/animation-tick').catch(function () {}); }
    if (now - started < 5000) requestAnimationFrame(tick);
    else fetch('/fp/animation-done?frames=' + frames).catch(function () {});
  }
  requestAnimationFrame(tick);
})();
