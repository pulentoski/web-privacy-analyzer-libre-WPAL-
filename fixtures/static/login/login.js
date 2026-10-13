// Fixture v1.4.1: el mismo login enviado como JSON (con claves anidadas) y como multipart.
document.getElementById('api').addEventListener('click', async function () {
  var user = document.getElementById('user').value;
  var clave = document.getElementById('clave').value;
  var otp = document.getElementById('otp').value;
  await fetch('/login/api', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user: user, password: clave, profile: {pin: 4321, newPassword: clave, note: 'visible'}, items: [{access_token: 'tok-' + clave}]}),
  });
  var form = new FormData();
  form.append('user', user);
  form.append('clave', clave);
  form.append('cvv', '987');
  form.append('comment', 'texto visible');
  await fetch('/login/upload', {method: 'POST', body: form});
  document.title = 'Fixture Login enviado';
});
