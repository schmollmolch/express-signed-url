Signed
======

_signed_ is tiny node.js library for signing urls and validating them based on secret key.

In short:

- With the help of this library, you can sign url, which will be used by user later.
- It verifies signature, when user uses this signed url. Ready to go "verify" express middleware included. (Although you can use this library without express.js as well)
- No session needed. No additional server storage needed.
- You can sign url and verify signature in different services/applications (as long as secret and hashing algorithm are the same).
- When signing an url, you can specify some additional limitations: allowed http method(s), user's ip and expiration time.

> Important!!!
> 
> Urls signed by version 1.x.x of this library are not valid with 2.x.x

How to use
===========

```bash
npm i signed
```

### Let's create signature object based on secret.

Signature object will be needed later to sign url, or to validate it.

```ts
import signed from 'signed';
const signature = signed({
    secret: 'secret string',
});
```

Possible options:
  - `secret: string` It MUST NOT be known for anyone else except you servers.
  - `ttl?: number` Default time to live for signed url (in seconds). If not set, signed url will be valid forever by default
  - `hash: string | HashFunction` What type of hash function should be used to sign url. `sha1` is used by default.
    But you can pass any other algorithm supported by [crypto.createHash()](https://nodejs.org/api/crypto.html#cryptocreatehashalgorithm-options).
    You can also pass your own hashing function `(input: string, secret: string) => string`.

### Let's sign url

```ts
const signedUrl = signature.sign('http://example.com/resource');
```
You also can optionally pass object with options:

```ts
const signedUrl = signature.sign('http://example.com/resource', {
    method: 'get',
});
```

Possible options:

 - `method?: string | string[]` List of http methods (as array, or separated by comma), which can be used.
   If not passed - any http method will be allowed.
 - `ttl?: number` Time to live for url starting from now (in seconds).
 - `exp?: number` Expiration unix timestamp (in seconds). Can be passed instead of ttl 
 - `addr?: string` Only this user's address will be allowed.
   You can pass user's address here to prevent sharing signed url with anyone else.
   
### Let's verify signature

So now, when you sent signed url to user, it's time to add verification for endpoints which should be accessible only with valid signature.

```ts
app.get('/resource', signature.verifier(), (req, res, next) => {
    res.send('ok');
});
```

You can also pass object with additional options to _verifier_ method.
Possible options:

 - `urlReader?: (req: Request) => string`
 
    By default verifier constructs original url as `${req.protocol}://${req.get('host')}${req.originalUrl}`.
 
    But if you use some kind of reverse proxy/load balancer/etc, external protocol/host/port can be different from those used by application.
    In that case you can pass you own method to build right correct external url to verify signature.

    e.g. `req => https://api.exmaple.com${req.originalUrl}`
 - `addressReader?: (req: Request) => string` Function which will be used to retrieve user's address (for the cases when you added address to signature).
   By default, `req => req.socket.remoteAddress` is used.
 - `blackholed?: RequestHandler` Handler to use in the case of wrong signature.

      (It's added for backward compatibility. It's better to not use it. See [Error handling](#error-handling)).
 
 - `expired?: RequestHandler` Handler to use in the case of valid, but expired signature.

     (It's added for backward compatibility. It's better to not use it. See [Error handling](#error-handling)).

### Using without express middleware

If you don't want to use it with express, you can just validate url with .verify(url, options) method:

```ts
const url = signature.sign('http://localhost:8080');

// ...

signature.verify(url); // returns "http://localhost:8080" or throws error
```

or:

```ts
const url = signature.sign('http://localhost:8080', {
    method: ['get', 'post'],
    addr: '127.0.0.1',
});

// ...

signature.verify(url, {
    method: 'get',
    addr: '127.0.0.1',
}); // returns "http://localhost:8080" or throws error
```

### Error handling

By default, if there is bad signature, verifier middleware throws SignatureError to the express _next_ function.

403 http status will be sent for bad signature and 410 if signature is expired.

You can handle these errors yourself, using express error handler middleware:  

```ts
import {SignatureError} from 'signed';

// ...

app.use((err, req, res, next) => {
    if (err instanceof SignatureError) {
        // signature is not valid or expired
    }
});
```

Or you can differentiate bad signature and expired signature this way:

```ts
import {BlackholedSignatureError, ExpiredSignatureError} from 'signed';

// ...

app.use((err, req, res, next) => {
    if (err instanceof BlackholedSignatureError) {
        // signature is not valid
    }
    if (err instanceof ExpiredSignatureError) {
        // signature is expired
    }
});
```

Example of application
----------------------

```ts
import * as express from 'express';
import signed from 'signed';

// Create signature
const signature = signed({
    secret: 'Xd<dMf72sj;6'
});

const app = express();

// Index with signed link
app.get('/', (req, res, next) => {
    const s = signature.sign('http://localhost:8080/source/a');
    res.send('<a href="'+s+'">'+s+'</a><br/>');
    // It prints something like http://localhost:8080/source/a?signed=r_1422553972-e8d071f5ae64338e3d3ac8ff0bcc583b
});

// Validating
app.get('/source/:a', signature.verifier(), (req, res, next) => {
    res.send(req.params.a);
});

app.listen(8080);
```

License
=======

MIT
