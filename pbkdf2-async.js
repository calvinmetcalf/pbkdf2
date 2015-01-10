var pbkdf2 = require('./pbkdf2-compat');
process.on('message', function(m) {
  process.send(pbkdf2.pbkdf2Sync(m.password, m.salt, m.iterations, m.keylen, m.digest).toString());
});