// Carga diferida al final del documento: solo se pide si el scroll llega abajo.
// Con ?infinite=1 la página crece cada vez que se acerca al final (scroll infinito): no tiene final alcanzable.
(function () {
  var infinite = new URLSearchParams(location.search).get('infinite') === '1';
  var sent = false;
  var observer = new IntersectionObserver(function (entries) {
    if (!entries[0].isIntersecting) return;
    if (infinite) {
      var more = document.createElement('div');
      more.style.height = '3000px';
      document.body.insertBefore(more, document.getElementById('bottom'));
      fetch('/v150/scroll-more');
    } else if (!sent) {
      sent = true;
      fetch('/v150/scroll-bottom');
    }
  });
  observer.observe(document.getElementById('bottom'));
})();
