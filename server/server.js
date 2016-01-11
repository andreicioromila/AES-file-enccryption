const app = require('express')();
const fs = require('fs');
const aesjs = require('aes-js');
const async = require('async');
const request = require('request');
const block_length = 8;

var iv = aesjs.util.convertStringToBytes("IVMustBe16Bytes.");

initialiseWebServer();

function initialiseWebServer() {
    app.get('/file/:mode/:name', function (req, res) {
        async.waterfall([
            retrieveKey,
            decryptKey,
            readFile,
            encryptFile,
            convertToBase64
        ], function done(err, file) {
            if (err) {
                res.status(400).send(err);
            }
            res.send(file);
        });

        function retrieveKey(cb) {
            request('http://localhost:8080/key/' + req.params.mode, {}, function (err, response, body) {
                if (err || response.statusCode != 200) {
                    return cb(err);
                }
                cb(null, body);
            });
        }

        function decryptKey(encryptedKey, cb) {
            var master_key = aesjs.util.convertStringToBytes("Example128BitKey");

            var data = aesjs.util.convertStringToBytes(encryptedKey, 'base64');

            var aesCfb = new aesjs.ModeOfOperation.cfb(master_key, iv, block_length);
            var decryptedBytes = aesCfb.decrypt(data);

            cb(null, decryptedBytes);
        }

        function readFile(key, cb) {
            fs.readFile(req.params.name, {} , function (err, file) {
                if (err) {
                    return cb(err);
                }
                cb(null, key, file);
            });
        }

        function encryptFile(key, file, cb) {
            var encryptedBytes;

            if (req.params.mode == 'cfb') {
                var aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, block_length);
                encryptedBytes = aesCfb.encrypt(file);

                cb(null, encryptedBytes);
            } else if (req.params.mode == 'ecb') {
                encryptedBytes = [];

                var aesEcb = new aesjs.ModeOfOperation.ecb(key);

                var chunks = splitTextInEqualChunks(file, 16);

                chunks.forEach(function (chunk) {
                    var encryptedChunk = aesEcb.encrypt(chunk);
                    encryptedBytes.push(encryptedChunk);
                });
                encryptedBytes = Buffer.concat(encryptedBytes);
                cb(null, encryptedBytes);
            } else {
                cb('Invalid operation mode');
            }
        }

        function convertToBase64(encryptedBytes, cb) {
            var encryptedText = aesjs.util.convertBytesToString(encryptedBytes, 'base64');
            cb(null, encryptedText)
        }
    });

    app.get('/', function (req, res) {
        res.send('All good!');
    });

    var webServer = app.listen(3000, function listen() {
        var host = webServer.address().address;
        var port = webServer.address().port;

        console.log('Web server listening at http://%s:%s', host, port);
    });
}

function splitTextInEqualChunks(text, length) {
    var chunks = [];
    var len = text.length;
    var i = 0;
    var chunk;
    var filler;

    while (i < len) {
        chunk = text.slice(i, i += length);
        filler = new Buffer(16 - chunk.length);
        filler.fill(0);
        chunk = Buffer.concat([chunk, filler]);
        chunks.push(chunk);
    }

    return chunks;
}