import {writeFileSync, readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath, parse as parseUrl} from 'node:url';
import express from 'express';
import {GithubEmailAuthentication} from '../index.js';

const PORT = 9099;
const CREDENTIALS_FILE_PATH = resolve(fileURLToPath(import.meta.url), '../test-credentials.json');

const app = express();
const credentials = {
        githubClientId: '',
        githubClientSecret: ''
    };

try {
    Object.assign(credentials, JSON.parse(readFileSync(CREDENTIALS_FILE_PATH).toString()));
} catch (err) {
    writeFileSync(CREDENTIALS_FILE_PATH, JSON.stringify(credentials, null, 2));
}

const {githubClientId, githubClientSecret} = credentials;

if (!githubClientId || !githubClientSecret) {
    console.warn('Missing Github test credentials in %s', CREDENTIALS_FILE_PATH);
    process.exit(1);
}

const _getResponseHtml = s => `<html lang="en"><body><p>${s}</p><a href="/">Go back</a></body></html>`;

const githubEmailAuth = new GithubEmailAuthentication({
    appOrRouter: app,
    routableCallbackUri: '/loginCallback',
    absoluteCallbackUrl: `http://localhost:${PORT}/loginCallback`,
    githubClientId,
    githubClientSecret,
    exposeAccessToken: false,
    onSuccess: (validatedPrimaryEmail, accessToken, req, res) => {
        console.log('Logged in with primary email "%s", token is %s', validatedPrimaryEmail, accessToken);
        res.send(_getResponseHtml(`You logged in as ${validatedPrimaryEmail}`));
    },
    onError: (message, res) => {
        console.warn('oh no, login failed for reason: %s', message);
        res.status(401);
        res.send(_getResponseHtml('Login failed. Reason: ' + message));
    },
});

app.get('/', function (req, res) {
    res.set('Content-Type', 'text/html');
    res.send(`<html lang="en">
                <body>
                  <p>Leave empty to login with *any* account, otherwise account's primary, verified email address:</p>
                  <form method="get" action="/login">
                    <input type="text" name="email" placeholder="email to login">
                    <button type="submit">Login</button>
                  </form>
                </body>
              </html>`);
});

app.get('/login', function(req, res) {
    let query = parseUrl(req.url, true).query,
        email = query.email || null;

    if (email) {
        console.log('Initiating github login for email %s', email);
        githubEmailAuth.startLoginForEmail(email, res);
    } else {
        console.log('Initiating github login for any account');
        githubEmailAuth.startLoginForUnknown(res);
    }
});

app.listen(PORT, function () {
    console.log(`Server running on http://localhost:${PORT}`);
});
