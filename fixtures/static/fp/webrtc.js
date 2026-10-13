// Intento de descubrir IPs por WebRTC (la política del worker lo bloquea).
(function () {
  try {
    var pc = new RTCPeerConnection({iceServers: []});
    pc.onicecandidate = function (event) { window.__fixtureIce = (window.__fixtureIce || 0) + 1; };
    pc.createDataChannel('fp');
    pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); }).catch(function () {});
  } catch (error) {}
})();
