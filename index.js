const assert = require('assert');
const crypto = require('crypto');
const {URL, URLSearchParams} = require('url');
const https = require('https');
const KeygripAutorotate = require('keygrip-autorotate');

const STATE_RANDOM_BYTES = 5;
const STATE_RANDOM_BYTES_STRING_LENGTH = STATE_RANDOM_BYTES * 2;
const MIN_ACCEPTED_STATE_LENGTH = STATE_RANDOM_BYTES_STRING_LENGTH + 29;
const MAX_ACCEPTED_STATE_LENGTH = 3500;
const DEFAULT_MAX_LOGIN_PROCESS_DURATION = 2 * 60 * 1000; // max. 2 minutes to enter credentials & hit Authorize
const DEFAULT_SCOPES = ['user:email'];
const ANY_EMAIL_PLACEHOLDER = '@' + crypto.randomBytes(10).toString('hex');

/**
 * @param {string} s
 * @return {string}
 */
function encodeSafeBase64(s) {
    return Buffer.from(s, 'utf8').toString('base64').replace(/[/+=]/g, s => s === '/' ? '_' : s === '+' ? '-' : '');
}

/**
 * @param {string} s
 * @return {*|String}
 */
function decodeUrlSafeBase64(s) {
    return s && Buffer.from(s.replace(/[-_]/g, s => s === '-' ? '+' : s === '_' ? '/' : ''), 'base64').toString('utf8');
}

/**
 * @param {string} payload - the plaintext value to put into the state
 * @param {KeygripAutorotate} signer
 * @return {string} a url-safe, signed state string that can be verified+decoded using {@link getPayloadFromStateIfVerified}
 */
function createSignedStateForPayload(payload, signer) {
    let encodedPayload = encodeSafeBase64(payload || ''),
        randomPrefix = crypto.randomBytes(STATE_RANDOM_BYTES).toString('hex'),
        textToSign = encodedPayload.length.toString(36) + '_' + randomPrefix + encodedPayload;

    return textToSign + signer.sign(textToSign);
}

/**
 *
 * @param {string} state
 * @param {KeygripAutorotate} signer
 * @return {string|null} the payload from the signed state IF the state could be verified, otherwise null
 */
function getPayloadFromStateIfVerified(state, signer) {
    if (!state || typeof state !== 'string' || state.length < MIN_ACCEPTED_STATE_LENGTH || state.length > MAX_ACCEPTED_STATE_LENGTH) {
        return null;
    }
    let payload = null;
    try {
        let lengthDividerIndex = state.indexOf('_');
        if (lengthDividerIndex > 3) {
            // encoded payload length can never be 36^4+
            return null;
        }
        let encodedPayloadLength = parseInt(state.substr(0, lengthDividerIndex), 36),
            encodedPayload = state.substr(lengthDividerIndex + 1 + STATE_RANDOM_BYTES_STRING_LENGTH, encodedPayloadLength),
            signedTextLength = lengthDividerIndex + 1 + STATE_RANDOM_BYTES_STRING_LENGTH + encodedPayloadLength,
            signedText = state.substr(0, signedTextLength),
            signature = state.substr(signedTextLength);

        // assert.equal(signedText.length + signature.length, state.length);

        if (signer.verify(signedText, signature)) {
            payload = decodeUrlSafeBase64(encodedPayload);
        }
    } catch (err) {
        // nothing
    }
    return payload;
}

/**
 * @param {URL} url - some Github url; must be https:
 * @param {?string} authToken
 * @param {number} [maxContentLength=2000]
 * @param {number} [timeout=15000]
 * @return {Promise<Object>}
 * @private
 */
function _fetchGithubJson(url, authToken, maxContentLength = 2000, timeout = 15000) {
    let headers = Object.create(null);
    headers['User-Agent'] = 'node.js';
    headers.Accept = 'application/json';
    if (authToken) {
        headers.Authorization = `token ${authToken}`;
    }

    if (url.protocol !== 'https:') {
        return Promise.reject('Expected https url, but got ' + url.protocol);
    }

    return new Promise((resolve, reject) => {
        let data = '';

        https.get({
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            headers,
            timeout
        }, res => {
            if (res.statusCode !== 200) {
                return reject('Github API responded with HTTP ' + res.statusCode);
            }
            // console.log('headers:', res.headers);

            res.on('data', d => data += d);

            res.on('end', () => {
                let json,
                    parsingError;
                try {
                    json = JSON.parse(data);
                } catch (err) {
                    parsingError = err
                }
                if (json) {
                    resolve(json)
                } else {
                    reject(parsingError || 'Invalid JSON in Github response');
                }
            });

        }).on('error', (e) => {
            // console.error(e);
            reject = reject && void reject(e);
        });
    });
}


/**
 * @param {Object} opts
 * @param {Router|Express.Application} opts.appOrRouter - some Express app or router
 * @param {string} opts.routableCallbackUri - e.g. '/githubCallback', this route will be added to the given `appOrRouter`
 *                                            to receive authorization codes
 * @param {string} opts.absoluteCallbackUrl - the absolute URL for the redirect from Github OAuth login, so basically
 *                                            the absolute URL for the `routableCallbackUri`.
 *                                            (!) Must equal the "Authorization callback URL" defined in the Github OAuth Apps setting.
 * @param {string} opts.githubClientId
 * @param {string} opts.githubClientSecret
 * @param {string} [opts.maxLoginProcessDuration] - the max. time in millis from initiating a login and the time
 *                                                  an authorization token is passed to the `routableCallbackUri` callback.
 *                                                  Essentially the time users have to enter their Github credentials
 *                                                  and authorize the app to access their email addresses.
 * @param {string} [opts.scopes] - scopes for the access token; defaults to {@link DEFAULT_SCOPES]
 *                                If given, the scopes must allow read-access to the user's Github email addresses ('user:email'),
 *                                otherwise login will fail.
 * @param {GithubEmailAuthentication_ErrorHandler} opts.onError
 * @param {GithubEmailAuthentication_SuccessHandler} opts.onSuccess
 * @param {boolean} [opts.exposeAccessToken=false] - if true, the access token will be passed to the `onSuccess` callback,
 *                                                   otherwise {@code null} is passed as token (default)
 * @param {boolean} [opts.logEnabled=false]
 *
 * @constructor
 */
function GithubEmailAuthentication(opts) {
    if (!this instanceof GithubEmailAuthentication) {
        return new GithubEmailAuthentication(opts);
    }

    const {
        appOrRouter,
        absoluteCallbackUrl,
        githubClientId,
        githubClientSecret,
        onError,
        onSuccess,
        logEnabled,
        scopes = DEFAULT_SCOPES,
        exposeAccessToken = false,
        maxLoginProcessDuration = DEFAULT_MAX_LOGIN_PROCESS_DURATION} = opts;

    assert(appOrRouter && typeof appOrRouter.get === 'function' && typeof appOrRouter.post === 'function',
        'Given appOrRouter must be express-like');
    assert(/^\/.+/.test(opts.routableCallbackUri), 'Invalid routableCallbackUri');
    assert(/^https?:\/\/.+$/.test(absoluteCallbackUrl), 'Invalid callback uri for Github OAuth');
    assert(githubClientId && typeof githubClientId === 'string', 'Invalid client id');
    assert(githubClientSecret && typeof githubClientSecret === 'string', 'Invalid client secret');
    assert(onError && typeof onError === 'function', 'Invalid onError callback');
    assert(onSuccess && typeof onSuccess === 'function', 'Invalid onSuccess callback');
    assert(!isNaN(maxLoginProcessDuration) && maxLoginProcessDuration > 1000, 'Invalid maxLoginProcessDuration');
    assert(Array.isArray(scopes), 'Invalid scopes array');

    const signer = new KeygripAutorotate({
        totalSecrets: 5,
        ttlPerSecret: maxLoginProcessDuration,
        hmacAlgorithm: 'sha256',
        encoding: 'hex'
    });

    const AUTH_BASE_URL = 'https://github.com/login/oauth/authorize?client_id=' + encodeURIComponent(githubClientId) +
                          '&scope=' + encodeURIComponent(scopes.join(' ')) +
                          '&redirectUri=' + encodeURIComponent(absoluteCallbackUrl) +
                          '&state=';

    /**
     * Start a Github OAuth authentication process, accepting any Github account with a primary, verified email address.
     * That email address will be passed to the {@link onSuccess} handler if authentication succeeds.
     *
     * @param {Response} res
     */
    this.startLoginForUnknown = (res) => this.startLoginForEmail(ANY_EMAIL_PLACEHOLDER, res);

    /**
     * Start a Github OAuth authentication process, accepting only for Github accounts
     * that have the given `emailAddress` as primary, verified email address, otherwise the error callback is called.
     *
     * @param {string} emailAddress
     * @param {Response} res
     */
    this.startLoginForEmail = function (emailAddress, res) {
        let trimmedEmail = (typeof emailAddress === 'string') ? emailAddress.trim() : null;

        if (!trimmedEmail || !trimmedEmail.includes('@')) {
            logEnabled && console.error('Invalid email address for GithubEmailAuthentication.startLoginForEmail(): "%s"', emailAddress);
            return setImmediate(onError, 'Bad email address', res, null);
        }

        let redirectUrl = AUTH_BASE_URL + createSignedStateForPayload(emailAddress, signer);

        res.redirect(302, redirectUrl);
    };


    /**
     * Destroys the signer and prevents any further logins.
     * Meant to be called before shutdown.
     */
    this.destroy = () => signer.destroy();

    appOrRouter.get(opts.routableCallbackUri, async (cbRequestFromGithub, res, next) => {
        /** @type {?string|undefined} */
        let code, state;

        const queryParamsIndex = cbRequestFromGithub.url.indexOf('?');
        if (queryParamsIndex >= 0) {
            try {
                // let's not rely on Express query parser being enabled, instead parse the query string manually
                const searchParams = new URLSearchParams(cbRequestFromGithub.url.substr(queryParamsIndex));
                code = searchParams.get('code');
                state = searchParams.get('state');
            } catch (err) {
                return setImmediate(onError, 'Failed to parse github callback url', res, next);
            }
        }

        if (!code) {
            return setImmediate(onError, 'Invalid authorization code received', res, next);
        }

        const emailFromVerifiedState = getPayloadFromStateIfVerified(state, signer);
        if (!emailFromVerifiedState) {
            return setImmediate(onError, 'Invalid or expired state for authentication', res, next);
        }

        let accessToken,
            loggedInPrimaryVerifiedEmail;

        try {
            const apiUrl = new URL('https://github.com/login/oauth/access_token');
            apiUrl.searchParams.set('client_id', githubClientId);
            apiUrl.searchParams.set('client_secret', githubClientSecret);
            apiUrl.searchParams.set('code', code);
            apiUrl.searchParams.set('state', state);
            const resJson = await _fetchGithubJson(apiUrl, null);

            accessToken = resJson && resJson['access_token'];

        } catch (err) {
            logEnabled && console.error('Github API call for access token failed with error: %s', err);
        }

        if (!accessToken) {
            return setImmediate(onError, 'Failed to retrieve access token', res, next);
        }

        try {
            const emailsArray = await _fetchGithubJson(new URL('https://api.github.com/user/emails'), accessToken, 20000);

            /**
             * @type {Object}
             * @property {string} email
             * @property {boolean} primary
             * @property {boolean} verified
             * @property {string} visibility
             */
            const acceptableEmailObject = emailsArray && emailsArray.find(e => e.verified && e.primary);

            loggedInPrimaryVerifiedEmail = acceptableEmailObject && acceptableEmailObject.email;

        } catch (err) {
            logEnabled && console.warn('Failed to fetch Github email addresses: %s', err);
        }

        if (!loggedInPrimaryVerifiedEmail) {
            return setImmediate(onError, 'Failed to determine primary, verified email address', res, next);
        }

        if (emailFromVerifiedState !== ANY_EMAIL_PLACEHOLDER && emailFromVerifiedState !== loggedInPrimaryVerifiedEmail) {
            logEnabled && console.warn('Expected Github account email "%s", but found primary, verified address "%s"',
                                         emailFromVerifiedState, loggedInPrimaryVerifiedEmail);

            return setImmediate(onError, 'Expected email address is not primary & verified address of the logged in Github account', res, next);
        }

        const tokenToExpose = exposeAccessToken ? accessToken : null;

        setImmediate(onSuccess, loggedInPrimaryVerifiedEmail, tokenToExpose, cbRequestFromGithub, res, next);
    });

    Object.freeze(this);
}

/**
 * @callback GithubEmailAuthentication_ErrorHandler
 * @param {string} errorMessage
 * @param {Response} response
 * @param {function|NextFunction} [next]
 */

/**
 * @callback GithubEmailAuthentication_SuccessHandler
 * @param {string} validatedPrimaryEmail
 * @param {string} accessToken
 * @param {Request} request
 * @param {Response} response
 * @param {function|NextFunction} [next]
 */


module.exports = {
    encodeSafeBase64,
    decodeUrlSafeBase64,
    createSignedStateForPayload,
    getPayloadFromStateIfVerified,
    GithubEmailAuthentication
};
