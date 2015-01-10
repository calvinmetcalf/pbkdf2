var crypto = require('crypto');
var fork = require('child_process').fork;
var path = require('path');
var compat = require('pbkdf2-compat');
var hashes = {
  sha1: 0,
  0: 'sha1',
  sha224: 1,
  1: 'sha224',
  sha256: 2,
  2: 'sha256',
  sha384: 3,
  3: 'sha384',
  sha512: 4,
  4: 'sha512'
};
function asyncpbkdf2(password, salt, iterations, keylen, digest, callback) {
  if (typeof iterations !== 'number') {
    throw new TypeError('Iterations not a number')
  }
  if (iterations < 0) {
    throw new TypeError('Bad iterations')
  }

  if (typeof keylen !== 'number') {
    throw new TypeError('Key length not a number')
  }

  if (keylen < 0) {
    throw new TypeError('Bad key length')
  }
  var msg = {
    password: password.toString(),
    salt: salt.toString(),
    iterations: iterations,
    keylen: keylen,
    digest: digest
  };

  var child = fork(path.resolve(__dirname, 'pbkdf2-async.js'));
  child.on('message', function (resp) {
    child.kill();
    callback(null, new Buffer(resp,'hex'));
  }).on('error', function (err) {
    child.kill();
    callback(err);
  });
  child.send(msg);
}
function handleError (err, callback) {
  if (typeof callback === 'function') {
    process.nextTick(function () {
      callback(err);
    });
  } else {
    throw err;
  }

}
exports.pbkdf2 = pbkdf2;
exports.pbkdf2Sync = pbkdf2Sync;
function pbkdf2Sync(password, salt, iterations, keylen, digest) {
  digets = digest || 'sha1';
  if (isNode10()) {
    if (digest === 'sha1') {
      return crypto.pbkdf2Sync(password, salt, iterations, keylen);
    } else {
      return compat.pbkdf2Sync(password, salt, iterations, keylen, digest);
    }
  } else {
    return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
  }
}
function pbkdf2(password, salt, iterations, keylen, digest, callback) {
  if (typeof digest ===  'function') {
    callback = digest;
    digest = 'sha1';
  }

  if (isNode10()) {
    if (digest === 'sha1') {
      return crypto.pbkdf2(password, salt, iterations, keylen, callback);
    } else {
      return asyncpbkdf2(password, salt, iterations, keylen, digest, callback);
    }
  } else {
    return crypto.pbkdf2(password, salt, iterations, keylen, digest, callback);
  }
}
var sha1 = '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164';
var isNode10Result;
function isNode10() {
  if (typeof isNode10Result === 'undefined') {
    isNode10Result = crypto.pbkdf2Sync('password', 'salt', 1, 32, 'sha256').toString('hex') === sha1;
  }
  return isNode10Result;
}