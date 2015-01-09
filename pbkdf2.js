var crypto = require('crypto');
var fork = require('child_process').fork;
var path = require('path');
var syncpbkdf2 = require('./pbkdf2-shim');
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
    callback(null, new Buffer(resp));
  }).on('error', function (err) {
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
exports.hash = pbkdf2;
function pbkdf2(password, salt, iterations, keylen, digest, callback) {
  if (typeof digest === 'function') {
    callback = digest;
    digest = 'sha1';
  }

  if (typeof iterations !== 'number') {
    return handleError(new TypeError('Iterations not a number'), callback);
  }

  if (iterations < 0){
    return handleError(new TypeError('Bad iterations'), callback);
  }

  if (typeof keylen !== 'number') {
    return handleError(new TypeError('Key length not a number'), callback);
  }

  if (keylen < 0) {
    return handleError(new TypeError('Bad key length'), callback);
  }
  if (!Buffer.isBuffer(password))  {
    password = new Buffer(password);
  }
  if (!Buffer.isBuffer(salt)) {
    salt = new Buffer(salt);
  }

  if (typeof callback !== 'function') {
    if (isNode10() && digest !== 'sha1') {
      return syncpbkdf2(password, salt, iterations, keylen, digest);
    } else {
      return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
    }
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