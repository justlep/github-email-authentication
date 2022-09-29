# github-email-authentication [![NPM Version][npm-image]][npm-url] [![Node.js Version][node-version-image]][node-version-url]

User authentication based on a Github account's verified, primary email address using Github OAuth.

Each authentication process can be started for either a _known_ email address or _any_ Github account's email address (as long as it's the primary, verified email address).
Upon successful authentication, the Github account's primary, verified email address and, 
optionally, the access token are passed to a given success handler. 
When authentication is started for a _known_ email address, that address is expected to be the logged-in 
Github account's _primary, verified_ email address, otherwise authentication fails.
  
### Requirements
* Node 14+
* Express (or similar, it's up to you)
* Your Github OAuth app providing Client ID and Client secret.  
  See: https://github.com/settings/developers

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
import {GithubEmailAuthentication} from 'github-email-authentication';
import express from 'express';

import {CLIENT_ID, CLIENT_SECRET, PORT} from './app-config.js'; 

const app = express();

const githubAuth = new GithubEmailAuthentication({
        appOrRouter: app,
        routableCallbackUri: '/loginCallback',
        absoluteCallbackUrl: `https://my-domain.tld:${PORT}/loginCallback`,
        githubClientId: CLIENT_ID,
        githubClientSecret: CLIENT_SECRET,
        exposeAccessToken: false,
        maxLoginProcessDuration: 2 * 60 * 1000,
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

Properties of the `opts` object for `new GithubEmailAuthentication(opts)`:


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| appOrRouter | <code>Express</code> or <code>Router</code> |  | some Express app or router |
| routableCallbackUri | <code>string</code> |  | e.g. '/githubCallback', this route will be added to the given `appOrRouter` to receive authorization codes |
| absoluteCallbackUrl | <code>string</code> |  | the absolute URL for the redirect from Github OAuth login, so basically the absolute URL for the `routableCallbackUri`. (!)  Must equal the "Authorization callback URL" defined in your OAuth App's settings on Github, see https://github.com/settings/developers.
| githubClientId | <code>string</code> |  |  |
| githubClientSecret | <code>string</code> |  |  |
| [scopes] | <code>string[]</code> | <code>['user:email']</code> | scopes for the access token; If given, the scopes must allow read-access to the user's Github email addresses ('user:email'), otherwise login will fail. |
| [exposeAccessToken] | <code>boolean</code> | <code>false</code> | if true, the access token will be passed to the `onSuccess` callback,  otherwise `null` is passed as token (default: false) |
| [maxLoginProcessDuration] | <code>number</code> | 2 * 60 * 1000 | the max. time in millis from initiating a login and the time an authorization token is passed to the `routableCallbackUri` callback.  Essentially the time users have to enter their Github credentials and authorize the app to access their email addresses. Technically, the time after which a `state` can no longer be verified since the secret used for signing it got rotated out. (default: 2 minutes) |
| onSuccess | [<code>GithubEmailAuthentication\_SuccessHandler</code>](#GithubEmailAuthentication_SuccessHandler) |  |  |
| onError | [<code>GithubEmailAuthentication\_ErrorHandler</code>](#GithubEmailAuthentication_ErrorHandler) |  |  |
| [logEnabled] | <code>boolean</code> | false | if true, errors/warning will be logged to the console (default: false).                                      (!) Logged messages may contain sensitive data like email addresses. |

### Notes

#### `exposeAccessToken` (default=false)
Set this `true` if you need the access token for anything beyond the authentication process.

#### `scopes` (default=`['user:email']`)
The default scope only allows read-access to Github accounts' email addresses.
Add any scopes you want to use the access token for beyond authentication (requires `exposeAccessToken` set true).
With custom scopes, make sure read-access to account email addresses remains possible, otherwise authentication will fail.


### GithubEmailAuthentication\_ErrorHandler : <code>function</code>

| Param | Type |
| --- | --- |
| errorMessage | <code>string</code> | 
| response | <code>Response</code> | 
| [next] | <code>function</code> | 

<a name="GithubEmailAuthentication_SuccessHandler"></a>

### GithubEmailAuthentication\_SuccessHandler : <code>function</code>

| Param | Type |
| --- | --- |
| validatedPrimaryEmail | <code>string</code> | 
| accessToken | <code>?string</code> | 
| request | <code>Request</code> | 
| response | <code>Response</code> | 
| [next] | <code>function</code> | 





## Credits

* [github-oauth](https://github.com/maxogden/github-oauth) for the inspiration 

## License 
[MIT](./LICENSE)



[npm-image]: https://img.shields.io/npm/v/github-email-authentication.svg
[npm-url]: https://npmjs.org/package/github-email-authentication
[node-version-image]: https://img.shields.io/node/v/github-email-authentication.svg
[node-version-url]: https://nodejs.org/en/download/
