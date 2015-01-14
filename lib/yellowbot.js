"use strict";

var querystring = require('querystring'),
    crypto = require('crypto'),
    rest = require('restler'),
    fs   = require('fs'),
    _ = require('underscore');

var api = exports;

api.PACKAGE = (function() {
    var json = fs.readFileSync(__dirname + '/../package.json', 'utf8');
    return JSON.parse(json);
}());

var debug = console.log;
api.debug = 0;
// if debug module is available, use it, and turn debugging on by default
try { debug = require('debug')(api.PACKAGE.name); api.debug = 1; } catch (e) { }

function encode_utf8(s) {
    // borrowed from http://ecmanaut.blogspot.com/2006/07/encoding-decoding-utf8-in-javascript.html
    return unescape(encodeURIComponent(s));
}

function hmac_sha256(payload, secret) {
    var hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload);
    return hmac.digest("hex");
}

api.create = function(params) {
    var api2 = Object.create(this);
    if (params) {
        api2.configure(params);
    }
    return api2;
};

api.configure = function (params) {

    this.server = {
        port: 80,
        timeout: 45 * 1000,
        headers: {
            Connection: "Keep-Alive",
            'User-Agent': 'node-yellowbot/' + api.PACKAGE.version
        }
    };

    // pointless to be this verbose
    if (params.api_key) {
        this.server.api_key = params.api_key;
    }

    if (params.api_secret) {
        this.server.api_secret = params.api_secret;
    }

    this.protocol = params.protocol || 'http';
    // add the client as a non-enumerable property so it won't spew in the CONFIG message
    Object.defineProperty(this, 'client', { enumerable: false, value: require(this.protocol) });

    Object.defineProperty(this, 'agent', { enumerable: false, value: new this.client.Agent() });
    // HACK: crank up the number of sockets we're allowed to hold on to 
    debug("upgrading maxSockets from %d to %d", this.agent.maxSockets, 30);
    this.agent.maxSockets = 30;

    this.base_path = params.base_path || '/api/';

    var host = params.host || 'www.yellowbot.com';
    this.server.host = host;
    this.server.headers.Host = host;

    //params.auth = "devel:0nly";

    if (params.auth) {
        this.server.headers.Authorization = 'Basic ' + new Buffer(params.auth, 'utf8').toString('base64');
    }

    if (api.debug) {
      debug("CONFIG: %j", this);
    }
};

api.login_url = function(params, host) {
    //console.log("params: ", params);
    if (!params) { params = {}; }
    if (!host) { host = this.server.host; }

    params = this.sign_params(params);
    var path = '/signin/partner/?' + querystring.stringify(params);
    return this.protocol + "://" + host + path;
};

api.sign_params = function(params) {
    params.api_ts = params.api_ts || Math.round((new Date()).getTime() / 1000);
    params.api_key = this.server.api_key;

    // remove any api_sig parameter that might have snuck in here.
    delete params.api_sig;

    var keys = _.keys(params).sort(),
        parameters = '';

    _.each(keys, function(k) {
        if (params[k] === null || typeof params[k] === 'undefined') {
            delete params[k];
        } else {
            var v = params[k];
            // for file uploads
            if (typeof v === 'object') {
                if (v.filename) {
                    v = v.filename;
                } else {
                    console.error("Don't know how to sign with key/object", k, v);
                }
            }
            parameters += k + v;
        }
    });

    return _.extend(
        { api_sig: hmac_sha256( encode_utf8(parameters), this.server.api_secret ) },
        params
    );
};

var _handle_response = function(endpoint, cb) {
    return function(res) {
        var data = null;

        if (api.debug) {
            debug('%s STATUS: %s ', endpoint, res.statusCode);
            if (api.debug > 1) debug('HEADERS: ' + JSON.stringify(res.headers));
        }

        res.setEncoding('utf8');
        var api_response = "";
        res.on('data', function(chunk) {
            debug("%s CHUNK: %d chars ", endpoint, chunk.length);
            //console.log("got chunk: ", chunk);
            api_response += chunk;
            // HACK: sometimes our requests are just not ending!  I can't tell if this is a server side
            // issue or a client side one, so here we attempt to parse the result, and force the end ourselves
            try {
              data = JSON.parse(api_response);
              debug("%s api_response seems to parse so forcing end", endpoint);
              res.emit('end');
            } catch (err) {
              debug("%s got a chunk but api_response does not yet parse as JSON: %s", endpoint, err)
              data = null;
            }
        } );
        res.once('end', function() {
          if (api.debug > 1) debug("RESPONSE: " + api_response);
            res.socket.end(); // HACK: force end the socket to override buggy keep-alive behavior
            if (res.statusCode >= 400) {
                debug("%s api error", endpoint, api_response);
                if (cb) { cb("API error", null); }
            }
            else {
                if (api.debug > 1) { debug("%s api response: %j", endpoint, api_response); }
                if (!data) {
                  try {
                    // sometimes (particularly on errors) we get JSON objects sent as text/html
                      // data = /\b(?:application|text)\/(?:json|javascript)\b/.test(res.headers['content-type'])
                      //     ? JSON.parse(api_response)
                      //     : new String(api_response);
                      data = JSON.parse(api_response);
                  } catch (err) {
                    if (/\b(?:application|text)\/(?:json|javascript)\b/.test(res.headers['content-type'])) {
                      // if it was supposed to be json send on the parse error
                      if (cb) return cb(err);
                    } else { 
                      // otherwise send the whole response as an error message
                      if (cb) return cb({ error: 'API response was not JSON', conent_type: res.headers['content-type'], api_response: new String(api_response) });
                    }
                    console.error(err);
                    return;
                  }
                }
                if (data.system_error && !data.error) {
                    data.error = data.system_error;
                }
                if (typeof data.error === 'undefined') {
                    data.error = null;
                }
                if (cb) { cb(data.error, data); }
            }
        });
        res.once('closed', function() {
          debug('%s CLOSED', endpoint);
        });
    };
};

api.get = function(endpoint, params, cb) {

    params = _.clone(params);
    if (!params) { params = {}; }
    params = this.sign_params(params);

    var path = this.base_path + endpoint + '?' + querystring.stringify(params);

    if (api.debug) { debug("GET:", this.server.host, path); }

    var req = this.client.request(
        _.extend({},
            this.server,
            {
                path: path,
                method: "GET",
                headers: this.server.headers,
                agent: this.agent
            }
        ),
        _handle_response(endpoint, cb)
    );

    debug("requests", this.agent.requests, "sockets", Object.keys(this.agent.sockets).map(function (k) { return this[k].length; }.bind(this.agent.sockets)).reduce(function (s,v) {return s+v;}));

    var socketAssignmentTimeout = setTimeout(function () {
      req.abort();
      cb({error: "timed out waiting for a socket"});
    }, 1000);

    req.once('socket', function(socket) {
      clearTimeout(socketAssignmentTimeout);
      debug("%s: assigned socket", endpoint);
      socket.setTimeout(10000, function () {
        debug("%s: socketTimeout fired, ending...", endpoint);
        socket.end();
      });
    });

    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
        if (cb) { cb(e.message); }
    });

    req.end();
};

api._send_json = function(method, endpoint, params, data, cb) {

    var body = new Buffer(JSON.stringify(data));

    params = _.clone(params);
    params = this.sign_params(params);

    var req = this.client.request(
        _.extend({},
            this.server,
            {
                method: method,
                path: this.base_path + endpoint + '?' + querystring.stringify(params),
                headers: _.extend({},
                    this.server.headers,
                    {
                        'Content-Type': 'application/json',
                        'Content-Length': body.length
                    }
                ),
                agent: this.agent
            }
        ),
        _handle_response(endpoint, cb)
    );

    req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
        if (cb) { cb(e.message); }
    });

    req.write(body.toString());
    if (api.debug) { debug("%s:", method, this.server.host, req.path); }
    req.end();
};

api.post = api._send_json.bind(api, 'POST');
api.put = api._send_json.bind(api, 'PUT');

api.post_form = function(endpoint, params, cb) {

    var url = this.protocol + "://" + this.server.host + this.base_path + endpoint;

    var has_files = false;

    _.each(params, function(v,k, p) {
       if (typeof v === 'object') {
           has_files = true;
           p[k] = rest.file( v.path, null, v.size, null, 'image/png' );
       }
    });

    params = _.clone(params);
    params = this.sign_params(params);

    var req = rest.post(url,
        _.extend({},
            this.server,
            {
                method: 'POST',
                multipart: has_files,
                data: params,
                parser: rest.parsers.json,
                headers: _.extend({},
                    this.server.headers,
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
        if (typeof data.error === 'undefined') {
            data.error = null;
        }
        if (cb) { cb(data.error, data); }
    });
};

api.log_action = function(params, data, cb) {
    this.post("reputation_management/log_action", params, data, cb);
};
