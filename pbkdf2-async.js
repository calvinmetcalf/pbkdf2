var pbkdf2 = require('./pbkdf2-shim');
process.on('message', function(m) {
  process.send(pbkdf2(new Buffer(m.password), new Buffer(m.salt), m.iterations, m.keylen, m.digest).toString());
});