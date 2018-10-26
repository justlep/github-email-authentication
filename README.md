# github-email-authentication [![NPM Version][npm-image]][npm-url] [![Node.js Version][node-version-image]][node-version-url]

User authentication based on verified, primary Github account email addresses using Github OAuth.

Allows the authentication process for either a _known_ or _any_ email address.
Upon successful authentication, the Github account's primary, verified email address and, 
optionally, the access token are passed to a given success handler. 
When authentication is started for a _known_ email address, that address is expected to be the logged-in 
Github account's _primary, verified_ email address, otherwise authentication fails.
  
### Security
* Using signed values for the `state` parameter (HMAC-SHA256), unique for each started
  login process and verified before accepting any authorization code. 
  Also, `state` expires after max. 2 minutes by using [rotating secrets](https://github.com/justlep/keygrip-autorotate) 
  for signing.
* Login processes started for a *known* email address will succeed only if
  that email address is really the Github account's primary, verified email.
* Github accounts with no verified, primary email addresses are rejected in all cases.  


## Usage

```javascript
const {GithubEmailAuthentication} = require('github-email-authentication');
const {express} = require('express');

const {CLIENT_ID, CLIENT_SECRET, PORT} = require('../some-config');
const app = express();

const githubAuth = new GithubEmailAuthentication({
        appOrRouter: app,
        routableCallbackUri: '/loginCallback',
        absoluteCallbackUrl: `https://my-domain.tld:${PORT}/loginCallback`,
        githubClientId: CLIENT_ID,
        githubClientSecret: CLIENT_SECRET,
        exposeAccessToken: false,
        onSuccess: (validatedPrimaryEmail, accessToken, req, res, next) => {
            // (1) `validatedPrimaryEmail` is never empty here
            // (2) `accessToken` is null here due to `exposeAccessToken: false`
            
            // TODO check who logged in & put customer into session or so
            
            res.redirect(302, '/account');
        },
        onError: (message, res, next) => {
            console.warn('Login failed, reason: %s', message);
            res.status(403).send('Login failed. Reason: ' + message);
        }
    });

app.post('/loginNewCustomer', (req, res) => {
    console.log('Initiating github login for any account');
    githubAuth.startLoginForUnknown(res);
});

app.post('loginExistingCustomer', (req, res) => {
    let {email} = req.query;
    console.log('Initiating github login for email %s', email);
    githubAuth.startLoginForEmail(email, res);
});

```

## Options
Mandatory options see [index.js](./index.js).

### Optional

#### `exposeAccessToken` (default=false)
Set this `true` if you need the access token for anything beyond the authentication process.
Notice that the default scopes only allow read-access to the account email addresses.

#### `scopes` (default=['user:email'])
Define all scopes you'll want to use the access token for. Make sure read-access to the 
account email addresses is possible, otherwise authentication will fail.

#### `maxLoginProcessDuration` (default=2 * 60 * 1000)
The maximum duration (in millis) for which the `state` of a user returning from
the login/authorization form at Github will be accepted. (Technically, the time after which
a `state` can no longer be verified since the secret used for signing it got rotated out).
 

#### `logEnabled` (default=false)
Enable for local development only, since logged messages will contain email addresses and access tokens.

## Credits

* [github-oauth](https://github.com/maxogden/github-oauth) for the inspiration 

## License 
[MIT](./LICENSE)



[npm-image]: https://img.shields.io/npm/v/github-email-authentication.svg
[npm-url]: https://npmjs.org/package/github-email-authentication
[node-version-image]: https://img.shields.io/node/v/github-email-authentication.svg
[node-version-url]: https://nodejs.org/en/download/
