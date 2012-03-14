"use strict";

var querystring = require('querystring'),
    http = require('http'),
    crypto = require('crypto'),
    rest = require('restler'),
    fs   = require('fs'),
    _ = require('underscore');

var api = exports;

api.PACKAGE = (function() {
    var json = fs.readFileSync(__dirname + '/../package.json', 'utf8');
    return JSON.parse(json);
}());

api.debug = 0;

api.server = {
    port: 80,
    timeout: 15 * 1000,
    headers: {
        Connection: "Keep-Alive",
        'User-Agent': 'node-yellowbot/' + api.PACKAGE.version
    }
};

var config = {};

function encode_utf8(s) {
    // borrowed from http://ecmanaut.blogspot.com/2006/07/encoding-decoding-utf8-in-javascript.html
    return unescape(encodeURIComponent(s));
}

function hmac_sha256(payload, secret) {
    var hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload);
    return hmac.digest("hex");
}

api.configure = function(params) {
    // pointless to be this verbose
    if (params.api_key) {
        config.api_key = params.api_key;
    }

    if (params.api_secret) {
        config.api_secret = params.api_secret;
    }

    if (!params.host) {
        params.host = 'www.yellowbot.com';
    }
    api.server.host = params.host;
    api.server.headers.Host = api.server.host;

    params.auth = "devel:0nly";

    if (params.auth) {
        api.server.headers.Authorization = 'Basic ' + new Buffer(params.auth, 'utf8').toString('base64');
    }
};

api.login_url = function(params) {
    //console.log("params: ", params);
    if (!params) { params = {}; }
    _sign(params);
    var path = '/signin/partner/?' + querystring.stringify(params);
    return "http://" + api.server.host + path;
};

function _sign(params) {

        params.api_ts = Math.round((new Date()).getTime() / 1000);
        params.api_key = config.api_key;

        // remove any api_sig parameter that might have snuck in here.
        delete params.api_sig;

        var parameters = "";
        var keys = _.keys(params).sort();
        _.each(keys, function(k) {
                if (typeof params[k] === 'undefined') {
                    delete params[k];
                }
                else {
                    var v = params[k];
                    // for file uploads
                    if (typeof v === 'object') {
                        if (v.filename) {
                            v = v.filename;
                        }
                        else {
                            console.error("Don't know how to sign with key/object", k, v);
                        }
                    }
                    parameters = parameters + ( parameters ? "" : "") + k + v;
                }
        });

        params.api_sig = hmac_sha256( encode_utf8(parameters), config.api_secret );

        // modifies the params structure in place, so not returning anything
}

var _handle_response = function(cb) {
    return function(res) {
        var data;
        //console.log('STATUS: ' + res.statusCode);
        //console.log('HEADERS: ' + JSON.stringify(res.headers));

        res.setEncoding('utf8');
        var api_response = "";
        res.on('data', function(chunk) {
            //console.log("got chunk: ", chunk);
            api_response += chunk;
        } );
        res.on('end', function() {
            if (res.statusCode >= 400) {
                console.log("api error", api_response);
                if (cb) { cb("API error", null); }
            }
            else {
                if (api.debug) { console.log("api response:", api_response); }
                try {
                    data = JSON.parse(api_response);
                }
                catch(err) {
                    console.log("Could not parse JSON:", err);
                    if (cb) { cb(err); }
                    return;
                }
                if (data.system_error && !data.error) {
                    data.error = data.system_error;
                }
                if (cb) { cb(data.error, data); }
            }
        });
    };
};

api.get = function(method, params, cb) {

    params = _.clone(params);
    if (!params) { params = {}; }
    _sign(params);

    var req = http.request(
        _.extend({},
            api.server,
            {
                path: '/api/' + method + '?' + querystring.stringify(params),
                method: "GET",
                headers: api.server.headers
            }
        ),
        _handle_response(cb)
    );
    // the timeout here doesn't seem to work...
    //req.setTimeout(3000, function(e) { console.log("timeout", e) });

    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
        if (cb) { cb(e.message); }
    });

    req.end();
};

api.post = function(method, params, data, cb) {

    var body = new Buffer(JSON.stringify(data));

    params = _.clone(params);
    _sign(params);

    var req = http.request(
        _.extend({},
            api.server,
            {
                method: 'POST',
                path: '/api/' + method + '?' + querystring.stringify(params),
                headers: _.extend({},
                    api.server.headers,
                    {
                        'Content-Type': 'application/json',
                        'Content-Length': body.length
                    }
                )
            }
        ),
        _handle_response(cb)
    );

    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
        if (cb) { cb(e.message); }
    });

    req.write(body.toString());
    req.end();
};


api.post_form = function(method, params, cb) {

    var url = "http://" + api.server.host + '/api/' + method;

    var has_files = false;

    _.each(params, function(v,k, p) {
       if (typeof v === 'object') {
           has_files = true;
           p[k] = rest.file( v.path, null, null, null, 'image/png' );
       }
    });

    params = _.clone(params);
    _sign(params);

    var req = rest.post(url,
        _.extend({},
            api.server,
            {
                method: 'POST',
                multipart: has_files,
                data: params,
                parser: rest.parsers.json,
                headers: _.extend({},
                    api.server.headers,
                    {}
                )
            }
        )
    ).on('complete', function(data) {
        if (data instanceof Error) {
            console.log('problem with request:', data);
            if (cb) { cb(data); }
            return;
        }
        if (data.system_error && !data.error) {
            data.error = data.system_error;
        }
        if (cb) { cb(data.error, data); }
    });
};

api.log_action = function(params, data, cb) {
    api.post("reputation_management/log_action", params, data, cb);
};
