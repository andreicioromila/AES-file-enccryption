const request = require('request');
const fs = require('fs');
const aesjs = require('aes-js');
const async = require('async');

var iv = aesjs.util.convertStringToBytes("IVMustBe16Bytes.");

var filename = 'test.txt';
var mode = 'cfb';

//var mode = 'ecb';

retrieveFile();

function retrieveFile() {
    async.waterfall([
        retrieveKey,
        decryptKey,
        retrieveFile,
        decryptFileData,
        convertToString,
        saveToFile
    ], function(err, text) {
        if (err) {
            throw new Error(err);
        }
        console.log(text);
    });

    function retrieveKey(cb) {
        request('http://localhost:8080/key/' + mode, {}, function (err, response, body) {
            if (err || response.statusCode != 200) {
                return cb(err);
            }
            cb(null, body);
        });
    }

    function decryptKey(encryptedKey, cb) {
        var master_key = aesjs.util.convertStringToBytes("Example128BitKey");

        var data = aesjs.util.convertStringToBytes(encryptedKey, 'base64');

        var aesCfb = new aesjs.ModeOfOperation.cfb(master_key, iv, 8);
        var decryptedBytes = aesCfb.decrypt(data);

        cb(null, decryptedBytes);
    }

    function retrieveFile(key, cb) {
        request('http://localhost:3000/file/' + mode + '/' + filename, function (err, response, body) {
            if (err || response.statusCode != 200) {
                return cb(err);
            }
            cb(null, key, body);
        });
    }

    function decryptFileData(key, fileContents, cb) {
        var decryptedBytes;
        var data = aesjs.util.convertStringToBytes(fileContents, 'base64');

        if (mode == 'cfb') {
            var aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, 8);
            decryptedBytes = aesCfb.decrypt(data);

            cb(null, decryptedBytes);
        } else if (mode == 'ecb') {
            var aesEcb = new aesjs.ModeOfOperation.ecb(key);
            decryptedBytes = [];

            var chunks = splitTextInEqualChunks(data, 16);

            chunks.forEach(function (chunk) {
                var decryptedChunk = aesEcb.decrypt(chunk);
                decryptedBytes.push(decryptedChunk);
            });
            decryptedBytes = Buffer.concat(decryptedBytes);

            cb(null, decryptedBytes);
        }
    }

    function convertToString(decryptedBytes, cb) {
        var decryptedText = aesjs.util.convertBytesToString(decryptedBytes);
        decryptedText = decryptedText.replace(/\0/g, '');
        cb(null, decryptedText);
    }

    function saveToFile(decryptedText, cb) {
        fs.writeFile(filename, decryptedText, {}, function(err) {
            if (err) {
                return cb(err);
            }
            cb(null, decryptedText);
        })
    }
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