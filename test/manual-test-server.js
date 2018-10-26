const express = require('express');
const url = require('url');
const app = express();
const {GithubEmailAuthentication} = require('..');

const PORT = 9099;
const CLIENT_ID = '__PUT_CLIENT_ID_HERE__';
const CLIENT_SECRET = '__PUT_CLIENT_SECRET_HERE__';

const githubEmailAuth = new GithubEmailAuthentication({
    appOrRouter: app,
    routableCallbackUri: '/loginCallback',
    absoluteCallbackUrl: `http://localhost:${PORT}/loginCallback`,
    githubClientId: CLIENT_ID,
    githubClientSecret: CLIENT_SECRET,
    exposeAccessToken: false,
    onSuccess: (validatedPrimaryEmail, accessToken, req, res, next) => {
        console.log('Logged in with primary email "%s", token is %s', validatedPrimaryEmail, accessToken);
        res.send(`You logged in as ${validatedPrimaryEmail}`);
    },
    onError: (message, res, next) => {
        console.warn('oh no, login failed for reason: %s', message);
        res.status(403).send('Login failed. Reason: ' + message);
    }
});

app.get('/', function (req, res) {
    res.set('Content-Type', 'text/html');
    res.send(`<html>
                <body>
                  <p>Leave empty to login with *any* account, otherwise account's primary, verified email address:</p>
                  <form method="get" action="/login">
                    <input type="text" name="email" placeholder="email to login">
                    <button type="submit">Login</button>
                  </form>
                </body>
              </html>`);
});

app.get('/login', function(req, res, next) {
    let query = url.parse(req.url, true).query,
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
