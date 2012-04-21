/* Imports */
var net = require('net');
var fs = require('fs');
var qs = require('querystring');
var express = require('express');

/* Configuration settings */
var SERVER_PORT = 39927;
var CLICK_PORT = 7777;

/* Useful regular expressions */
var r_packet_url = /\/(bad|good)_packets/i;
var r_fw_config_url = /\/rules/i;
var r_fw_config_response = /(.|\W)*DATA \d+\W+(.*)/i;

/* App object includes the HTTP server */
var app = express.createServer();
/* JSON parsing of bodies, among other things */
app.use(express.bodyParser());

/* Communicating with Click */
var do_click = function(command, callback) {
    var socket = net.createConnection(CLICK_PORT, function() {
        socket.setEncoding('ascii');
        socket.on('data', callback);
        socket.end(command);
    });
};

var rules = [];
do_click('READ ipf.config\n', function(data) {
    if (r_fw_config_response.test(data)) {
        console.log(data);
        var config = data.match(r_fw_config_response)[2];
        var rls = config.split(',');
        for (var i in rls) {
            rls[i] = rls[i].trim();
        }
        rules = rls;
    }
    console.log(rules);
});

/* Respond to HTTP requests.. */
// app.get(r_packet_url, function (req, res) {
//     var filename = '/home/firewall/' + req.params[0] + '_packets.log';
//     fs.readFile(filename, function (err, data) {
//         if (err) throw err;
//         res.send(data);
//         console.log('Served ' + filename);
//     });
// });

/* GET /rules */
app.get(r_fw_config_url, function (req, res) {
    do_click('READ ipf.config\n', function(data) {
        console.log(Object.prototype.toString.call(data) + ': ' + data);
        var config = data.match(r_fw_config_response)[2];
        var rules = config.split(',');
        for (var i in rules) {
            rules[i] = rules[i].trim();
        }

        var client_config = rules.filter(function (el) {
            return (el.indexOf('1 dst ' + req.query.client) !== -1);
        }).map(function (el) {
            return el.split('1 dst ' + req.query.client + ' and ').reduce(function (a, b) {
                return a + b;
            });
        }).join(', ');
        res.send(client_config);
    });
});

/**
 * POST /rules
 * @param req.body.client     IP address for client
 * @param req.body.rule       Rule configuration string
 * @param req.body.operation  'add' or 'remove'
 */
app.post(r_fw_config_url, function (req, res) {
    switch (req.body.operation) {
    case 'remove':
        rules = rules.filter(function (el) {
            return el !== '1 dst ' + req.body.client + ' and ' + req.body.rule;
        });
        break;
    case 'add':
        rules.unshift('1 dst ' + req.body.client + ' and ' + req.body.rule);
        break;
    default:
        return;
    }

    var set_config_string = 'WRITEDATA ipf.config ';
    var new_config = rules.join(', ');
    set_config_string += new_config.length;
    set_config_string += '\n' + new_config;
    console.log('setting config string');
    do_click(set_config_string, function () {
        res.send('new firewall config written');
    });
});

app.listen(SERVER_PORT);
console.log('listening on http://0.0.0.0:' + SERVER_PORT);

/**
 * How to test:
 *  curl "http://localhost:39927/rules?client=1.1.1.1"
 *  curl -F 'client=1.1.1.1' -F 'rule=dst port 80' -F 'operation=add' http://localhost:39927/rules
 *  curl "http://localhost:39927/rules?client=1.1.1.1"
 *  curl -F 'client=1.1.1.1' -F 'rule=dst port 80' -F 'operation=remove' http://localhost:39927/rules
 */
