var crypto = require('crypto');
module.exports = pbkdf2;
function pbkdf2(password, salt, iterations, keylen, digest) {

  var hLen, l = 1, r, T;
  var derivedKey = new Buffer(keylen);
  var block1 = new Buffer(salt.length + 4);
  salt.copy(block1, 0, 0, salt.length);
  var U,j,k;
  var i = 0;
  while (++i <= l) {
    block1.writeUInt32BE(i, salt.length);

    U = crypto.createHmac(digest, password).update(block1).digest();

    if (!hLen) {
      hLen = U.length;
      T = new Buffer(hLen);
      l = Math.ceil(keylen / hLen);
      r = keylen - (l - 1) * hLen;

      if (keylen > (Math.pow(2, 32) - 1) * hLen) {
        throw new TypeError('keylen exceeds maximum length');
      }
    }

    U.copy(T, 0, 0, hLen);
    j = 0;
    while (++j < iterations) {
      U = crypto.createHmac(digest, password).update(U).digest();
      k = -1;
      while (++k < hLen) {
        T[k] ^= U[k];
      }
    }

    var destPos = (i - 1) * hLen;
    var len = (i == l ? r : hLen);
    T.copy(derivedKey, destPos, 0, len);
  }

  return derivedKey;
}
