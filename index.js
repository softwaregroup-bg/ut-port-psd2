/* eslint no-console: 0 */
const request = (process.type === 'renderer') ? require('ut-browser-request') : require('request');
const Hapi = require('hapi');
const hrtime = require('browser-process-hrtime');
const uuid = require('uuid');
const crypto = require('crypto');
const utCrypt = require('ut-crypt');
const fs = require('fs');
const querystring = require('querystring');
const cacheMap = fs.existsSync('cache.json') ? JSON.parse(fs.readFileSync('cache.json')) : {};
const openapi = require('./openapi');
const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const cache = (value, {key: {id, segment}, operation, ttl}) => {
    switch (operation) {
        case 'set':
            if (!cacheMap[segment]) cacheMap[segment] = {};
            cacheMap[segment][id] = {
                time: Date.now() + ttl * 1000,
                value
            };
            fs.writeFileSync('cache.json', JSON.stringify(cacheMap, false, 2));
            break;
        case 'get': {
            const result = cacheMap[segment] && cacheMap[segment][id];
            if (result && Date.now() < result.time) {
                console.log('cache hit', segment, id);
                return result.value;
            } else if (result) {
                console.log('cache miss', segment, id);
                delete cacheMap[segment][id];
            } else {
                console.log('cache miss', segment, id);
            }
            break;
        }
    };
};

module.exports = ({utPort, registerErrors, utMethod}) => class Psd2Port extends utPort {
    get defaults() {
        return {
            type: 'psd2',
            namespace: [
                'dskSandbox',
                'ingSandbox',
                'raboSandbox',
                'swedbankSandbox',
                'finastraSandbox'
            ],
            capture: {
                name: 'psd2'
            },
            server: {
                port: 80
            }
        };
    }

    exec(msg, $meta) {
        const [profileName, ...parts] = $meta.method.split('.');
        const method = this.findHandler(parts.join('.'));
        if (method) {
            return method.call(this, {profileName, profile: this.config.profiles[profileName], ...msg}, $meta);
        } else {
            return this.sendRequest(msg && {
                params: msg.params || msg,
                body: msg.body,
                headers: msg.headers
            }, $meta);
        };
    }

    handlers() {
        return {
            'consent.redirect': ({profile, ...params}) => {
                const url = new URL(profile.redirect);
                url.searchParams.set('state', this.encrypt({
                    typ: 'consent',
                    pfl: params.profileName,
                    id: params.userId,
                    cns: params.type,
                    acc: params['account-id']
                }));
                return url.href;
            }
        };
    }

    async sendRequest({profile, method, path, idHeader = 'X-Request-ID', keyId, params, body, form, headers = {}}, $meta) {
        const profileName = $meta && $meta.method && $meta.method.split('.')[0];
        profile = profile || this.config.profiles[profileName];
        keyId = keyId || profile.keyId;
        let url;
        const id = uuid.v4();
        const date = new Date().toUTCString();
        if (form) {
            body = querystring.stringify(form);
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...headers
            };
        }
        if (body && typeof body === 'object') {
            body = JSON.stringify(body);
            headers = {
                'Content-Type': 'application/json',
                ...headers
            };
        }
        const digest = 'SHA-256=' + crypto.createHash('sha256').update(body || '').digest().toString('base64');
        if ($meta && $meta.method) {
            const token = await this.getToken(profile, profileName, params.userId);
            if (token.keyId) keyId = token.keyId;
            headers.Authorization = 'Bearer ' + token.accessToken;
            headers['x-envoy-decorator-operation'] = $meta.method;
            params = await openapi({
                Date: date,
                Digest: digest,
                'TPP-Signature-Certificate': profile.signCert && profile.signCert.replace(/\r|\n/g, ''),
                'X-Request-ID': id,
                ...params
            }, $meta.method, this.config.path);
            const paramsHandler = this.findHandler($meta.method.split('.')[0] + '.params');
            if (paramsHandler) params = await paramsHandler({params, profile}, $meta);
            method = params.method;
            url = new URL(params.url);
            Object.assign(headers, params.headers);
        } else {
            url = new URL(path, profile.base);
            headers = {
                Date: date,
                ...headers
            };
            if (idHeader && profile.signCert) {
                headers = {
                    'TPP-Signature-Certificate': profile.signCert.replace(/\r|\n/g, ''),
                    Digest: digest,
                    ...headers
                };
            }
        }
        let signature;
        if (idHeader && profile.signCert) {
            const lines = [];
            const names = [];
            for (const header of profile.sign.headers) {
                switch (header) {
                    case '(request-target)':
                        lines.push(`(request-target): ${method.toLowerCase()} ${url.pathname}${url.search}`);
                        names.push(header);
                        break;
                    case '(id)':
                        lines.push(`${idHeader.toLowerCase()}: ${id}`);
                        names.push(idHeader.toLowerCase());
                        break;
                    default:
                        lines.push(`${header.toLowerCase()}: ${headers[header]}`);
                        names.push(header.toLowerCase());
                }
            }
            signature = crypto.createSign(profile.sign.algorithm).update(lines.join('\n')).end().sign(profile.signKey).toString('base64');
            signature = `keyId="${keyId}",algorithm="rsa-${profile.sign.algorithm}",headers="${names.join(' ')}",signature="${signature}"`;
        }
        if (headers.Authorization) {
            if (signature) headers.Signature = signature;
        } else {
            headers.Authorization = `Signature ${signature}`;
        }
        headers = {
            'User-Agent': 'ut',
            Date: date,
            Accept: 'application/json',
            ...headers
        };
        if (idHeader) headers[idHeader] = id;
        return new Promise((resolve, reject) => {
            this.httpClient({
                method: method.toLowerCase(),
                url: url.href,
                cert: profile.tlsCert,
                key: profile.tlsKey,
                headers,
                gzip: true,
                body
            }, (error, response, resultBody) => {
                if (response && (response.statusCode < 200 || response.statusCode >= 300)) {
                    console.log([
                        `${method.toUpperCase()} ${url.href}`,
                        ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
                        `${body ? ('\n' + body) : ''}`,
                        ''
                    ].join('\n'));
                    error = error || new Error(`${url.href} => ${response && response.statusCode} ${response && response.statusMessage} ${'\n' + JSON.stringify(resultBody)}`);
                }
                if (error) {
                    reject(error);
                } else {
                    const result = JSON.parse(resultBody);
                    if ($meta && $meta.method) {
                        const resultHandler = this.findHandler($meta.method.split('.')[0] + '.result');
                        if (resultHandler) {
                            resolve(resultHandler({result, profile}, $meta));
                            return;
                        }
                    }
                    resolve(result);
                }
            });
        });
    }

    wait() {
        const state = uuid.v4();
        const code = new Promise((resolve, reject) => {
            this.waiting[state] = {resolve, reject, time: hrtime()};
        });
        return {
            state,
            code
        };
    }

    async authorizeBasic(profile, profileName, cacheId, wait) {
        const url = new URL(profile.authorizePath, profile.base);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', profile.clientId);
        url.searchParams.set('redirect_uri', profile.redirect);
        url.searchParams.set('scope', profile.scope);
        if (wait) {
            const {code, state} = this.wait();
            url.searchParams.set('state', state);
            console.log(url.href);
            return this.tokenFromAuthorization(profile, {
                code: await code,
                authorization: 'Basic ' + Buffer.from(`${profile.clientId}:${profile.clientSecret}`).toString('base64')
            }, cacheId);
        } else {
            url.searchParams.set('state', this.encrypt({
                typ: 'authz',
                pfl: profileName,
                id: cacheId
            }));
            const error = new Error('Authorization required');
            error.type = 'psd2.redirect';
            error.redirect = url.href;
            throw error;
        }
    }

    encrypt(data) {
        return this.cbc.encrypt(JSON.stringify(data)).toString('hex');
    }

    decrypt(data) {
        const x = this.cbc.decrypt(Buffer.from(data, 'hex'));
        return JSON.parse(x);
    }

    async authorizeIng(profile, profileName, cacheId) {
        let result = await cache(false, {operation: 'get', key: {segment: 'app', id: cacheId}});
        if (result) return result;
        const tokens = await this.sendRequest({
            profile,
            method: 'post',
            path: 'oauth2/token',
            idHeader: 'X-ING-ReqID',
            form: {
                grant_type: 'client_credentials'
            }
        });
        if (tokens) {
            result = {
                keyId: tokens.client_id,
                code: '8b6cd77a-aa44-4527-ab08-a58d70cca286',
                authorization: 'Bearer ' + tokens.access_token,
                raw: tokens
            };
            await cache(result, {operation: 'set', key: {segment: 'app', id: profile.clientId}, ttl: tokens.expires_in});
        }
        return result;
    };

    async tokenFromAuthorization(profile, code, cacheId) {
        let result = await this.sendRequest({
            profile,
            keyId: code.keyId,
            method: 'post',
            path: profile.tokenPath,
            idHeader: profile.tokenIdHeader,
            form: {
                grant_type: 'authorization_code',
                redirect_uri: profile.redirect,
                code: code.code
            },
            headers: {
                Authorization: code.authorization
            }
        });
        if (result) {
            await cache({
                keyId: code.keyId,
                authorization: code.authorization,
                token: result.refresh_token
            }, {operation: 'set', key: {segment: 'refresh', id: cacheId}, ttl: result.refresh_token_expires_in || result.refresh_expires_in || profile.refreshExpiresIn});

            const ttl = result.expires_in;

            result = {
                keyId: code.keyId,
                scope: result.scope && result.scope.split(' '),
                accessToken: result.access_token,
                raw: result
            };
            await cache(result, {operation: 'set', key: {segment: 'access', id: cacheId}, ttl});
        }
        return result;
    }

    async tokenFromRefresh(profile, refreshToken, cacheId) {
        let result = await this.sendRequest({
            profile,
            keyId: refreshToken.keyId,
            method: 'post',
            path: profile.tokenPath,
            idHeader: profile.tokenIdHeader,
            form: {
                grant_type: 'refresh_token',
                refresh_token: refreshToken.token
            },
            headers: {
                Authorization: refreshToken.authorization
            }
        });
        const ttl = result.expires_in;
        result = {
            keyId: refreshToken.keyId,
            scope: result.scope.split(' '),
            accessToken: result.access_token,
            raw: result
        };
        await cache(result, {operation: 'set', key: {segment: 'access', id: cacheId}, ttl});
    }

    async getToken(profile, profileName, userId = 0) {
        const cacheId = userId + '/' + profile.clientId;
        let result = await cache(false, {operation: 'get', key: {segment: 'access', id: cacheId}});
        if (result) return result;
        const refreshToken = await cache(false, {operation: 'get', key: {segment: 'refresh', id: cacheId}});
        if (refreshToken) {
            result = await this.tokenFromRefresh(profile, refreshToken, cacheId);
        } else {
            result = await this[profile.authorize || 'authorizeBasic'](profile, profileName, cacheId);
        }
        return result;
    };

    async updateConsent({bank, id, type, account}) {
        const data = await utMethod('cache')(true, {
            cache: {
                operation: 'get',
                key: {
                    id,
                    segment: `${bank}.consent.account`
                }
            }
        });
        await utMethod('psd2.consent.getConsentStatus')({...data.params, consentId: data.id});
    }

    async init() {
        const result = await super.init(...arguments);
        if (!this.config.key) throw new Error(`Missing configuration ${this.config.id}.key`);
        this.cbc = utCrypt.prototype.cbc(this.config.key);
        this.httpServer = new Hapi.Server(this.config.server);
        if (this.config.capture) {
            await this.httpServer.register({
                plugin: require('ut-function.capture-hapi'),
                options: {name: this.config.id + '-receive', ...this.config.capture}
            });
        }
        this.httpClient = this.config.capture ? require('ut-function.capture-request')(request,
            {name: this.config.id + '-send', ...this.config.capture}) : request;
        return result;
    }

    async start() {
        const result = await super.start(...arguments);
        this.pull({exec: this.exec}, {requests: {}});
        this.waiting = {};
        this.httpServer.route({
            method: 'GET',
            path: '/redirect',
            handler: async(request, h) => {
                if (uuidRegex.test(request.query.state)) {
                    const code = request.query.code && request.query.state && this.waiting[request.query.state];
                    if (code) {
                        delete this.waiting[request.query.state];
                        code.resolve(request.query.code);
                        return h.response('Successful identification')
                            .header('x-envoy-decorator-operation', 'redirect');
                    } else {
                        return h.response('Invalid state or code').code(404);
                    }
                } else {
                    const params = this.decrypt(request.query.state);
                    const profile = this.config.profiles[params.pfl];
                    switch (params.typ) {
                        case 'authz':
                            await this.tokenFromAuthorization(profile, {
                                code: request.query.code,
                                authorization: 'Basic ' + Buffer.from(`${profile.clientId}:${profile.clientSecret}`).toString('base64')
                            }, params.id);
                            break;
                        case 'consent':
                            await this.updateConsent({
                                bank: params.pfl,
                                id: params.id,
                                type: params.cns,
                                account: params.acc
                            });
                    };
                    return h.response('Successful identification')
                        .header('x-envoy-decorator-operation', 'redirect');
                }
            }
        });
        this.expire = setInterval(() => {
            Object.entries(this.waiting).forEach(([name, value]) => {
                if (!value || !value.time || hrtime(value.time)[0] >= 5 * 60) {
                    this.waiting[name].reject(new Error('Timeout expired'));
                    delete this.waiting[name];
                };
            });
        }, 10000);
        this.httpServer.route({
            method: 'GET',
            path: '/healthz',
            options: {
                auth: false,
                handler: (request, h) => {
                    const code = this.isReady ? 200 : 202;
                    return h.response({state: this.state}).code(code);
                }
            }
        });
        await this.httpServer.start();
        return result;
    }

    async stop() {
        if (this.expire) {
            clearInterval(this.expire);
            this.expire = false;
        }
        if (this.httpServer) {
            await this.httpServer.stop();
            delete this.httpServer;
        }
        return super.stop(...arguments);
    }
};
