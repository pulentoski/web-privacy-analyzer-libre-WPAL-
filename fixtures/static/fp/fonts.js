// Enumeración de fuentes: mide el mismo texto con 60 familias distintas.
(function () {
  var families = [];
  for (var i = 0; i < 60; i++) families.push('FixtureFont' + i);
  var ctx = document.createElement('canvas').getContext('2d');
  var widths = [];
  for (var j = 0; j < families.length; j++) {
    ctx.font = "72px '" + families[j] + "', monospace";
    widths.push(ctx.measureText('mmmmmmmmmmlli').width);
  }
  window.__fixtureFontWidths = widths.length;
})();
