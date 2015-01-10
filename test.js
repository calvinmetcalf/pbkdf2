// tests based off https://github.com/dcousens/pbkdf2-compat/blob/9624836014c4976f8907273a4a77020b51a4fe8c/test/index.js

var test = require('tape');
var fixtures = require('./fixtures.json');
var pbkdf2 = require('./pbkdf2');

function testValid(key, salt, iterations, dkLen, algo, result) {
  test('key:'+ key + ' salt:' + salt + ' iterations:' + iterations + ' len:' + dkLen + ' algo:' + algo, function (t) {
    t.plan(3);
    var syncDone = false;
    pbkdf2.pbkdf2(key, salt, iterations, dkLen, algo, function (err, res) {
      t.equals(res.toString('hex'), result, 'async');
      t.ok(syncDone, 'async is actually async');
    });
    t.equals(pbkdf2.pbkdf2Sync(key, salt, iterations, dkLen, algo).toString('hex'), result, 'sync');
    syncDone = true;
  });
}
fixtures.valid.forEach(function (item) {
  Object.keys(item.results).forEach(function (algo) {
    testValid(item.key, item.salt, item.iterations, item.dkLen, algo, item.results[algo]);
  });
});
function testinValid(key, salt, iterations, dkLen, algo) {
  test('key:'+ key + ' salt:' + salt + ' iterations:' + iterations + ' len:' + dkLen + ' algo:' + algo, function (t) {
    t.plan(2);
    t.throws(pbkdf2.pbkdf2.bind(null, key, salt, iterations, dkLen, algo, function () {}), 'async');
    t.throws(pbkdf2.pbkdf2Sync.bind(null, key, salt, iterations, dkLen, algo), 'sync');
    syncDone = true;
  });
}
fixtures.invalid.forEach(function (item) {
  ['sha1', 'sha256', 'sha512'].forEach(function (algo) {
    testinValid(item.key, item.salt, item.iterations, item.dkLen, algo);
  });
});
test('defaults to sha1', function (t) {
  t.plan(3);
  var result = '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164';
  var syncDone = false;
  pbkdf2.pbkdf2('password', 'salt', 1, 32, function (err, res) {
    t.equals(res.toString('hex'), result, 'async');
    t.ok(syncDone, 'async is actually async');
  });
  t.equals(pbkdf2.pbkdf2Sync('password', 'salt', 1, 32).toString('hex'), result, 'sync');
  syncDone = true;
});