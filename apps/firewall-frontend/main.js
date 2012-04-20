/* Imports */
var net = require('net');
var fs = require('fs');
var qs = require('querystring');
var express = require('express');

/* Configuration settings */
var SERVER_PORT = 39927;
var CLICK_PORT = 7777;

/* Useful regular expressions for routing */
var r_packet_url = /\/(bad|good)_packets/i;
var r_fw_config_url = /\/fw_config/i;
var r_fw_config_response = /DATA \d+\W+(.*)/i;

/* Our app object includes the http server */
var app = express.createServer();
/* JSON parsing of bodies, among other things */
app.use(express.bodyParser());

/* Respond to requests.. */

app.get(r_packet_url, function (req, res) {
    var filename = '/home/firewall/' + req.params[0] + '_packets.log';
    fs.readFile(filename, function (err, data) {
        if (err) throw err;
        res.send(data);
        console.log('Served ' + filename);
    });
});

app.get(r_fw_config_url, function (req, res) {
    var socket = net.createConnection(CLICK_PORT, function() {
        socket.setEncoding('ascii');
        socket.on('data', function(data) {
            console.log(Object.prototype.toString.call(data) + ': ' + data);
            if (r_fw_config_response.test(data)) {
                var config = data.match(r_fw_config_response);
                res.send(config[1]);
            }
        });
        socket.end('READ ipf.config\n', function() {
            console.log('socket: READ');
        });
    });
});

app.post(r_fw_config_url, function (req, res) {
    var socket = net.createConnection(CLICK_PORT, function() {
        console.log('Handling POST request: ');
        console.log(req.body.config);
        var set_config_string = 'WRITEDATA ipf.config ';
        set_config_string += req.body.config.length;
        set_config_string += '\n' + req.body.config;
        socket.end(set_config_string, function () {
            res.send('\'' + req.body.config + '\' written as new firewall config');
        });
    });
});

app.listen(SERVER_PORT);
console.log('listening on 0.0.0.0:' + SERVER_PORT);

/**
POST /fw_config

1 dst port 80, 1 src port 80, 0 all
*/
