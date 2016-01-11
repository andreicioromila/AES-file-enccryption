const app = require('express')();
const aesjs = require('aes-js');
const async = require('async');
const keys = require('./config.json');

var iv = aesjs.util.convertStringToBytes("IVMustBe16Bytes.");

initialiseWebServer();

function initialiseWebServer() {
    app.get('/key/:mode', function (req, res) {
        async.waterfall([
            encryptKey,
            convertToBase64
        ], function done(err, key) {
            if (err) {
                res.status(400).send(err);
            }
            res.send(key);
        });

        function encryptKey(cb) {
            var master_key = aesjs.util.convertStringToBytes(keys.master);
            var opMode = req.params.mode;

            var aesCfb = new aesjs.ModeOfOperation.cfb(master_key, iv, 8);
            var encryptedBytes = aesCfb.encrypt(keys[opMode]);

            cb(null, encryptedBytes);
        }

        function convertToBase64(encryptedBytes, cb) {
            console.log(req.params.mode, encryptedBytes);
            var encryptedText = aesjs.util.convertBytesToString(encryptedBytes, 'base64');
            cb(null, encryptedText);
        }
    });

    app.get('/', function (req, res) {
        res.send('All good!');
    });

    var webServer = app.listen(8080, function listen() {
        var host = webServer.address().address;
        var port = webServer.address().port;

        console.log('Web server listening at http://%s:%s', host, port);
    });
}
