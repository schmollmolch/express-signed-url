# express-signed-url

![build](https://github.com/schmollmolch/express-signed-url/actions/workflows/build.yaml/badge.svg)

express-signed-url is tiny node.js/express library for signing urls and validating them based on secret key.

It might be used for secure sharing urls for users, without need to check permissions on resources server.

E.g.

You have front server, which generates html or supports RESTFull API. And you have data server, which provides some resources.

With the help of this library you may sign urls on front server and give them to end users. After that, you may verify signature on data server.

So, sessions or storing additional data aren't required.

This is a shameless clone of [signed](https://github.com/smbwain/signed) that is extended for sha256 as hash algorithm and works successfully behind a reverse proxy.

## Let's start

```bash
npm install --save express-signed-url
```

Create signature object based on secret.

Secret string should not be known for anyone else, except your servers

```ts
import signed from 'express-signed-url'
const signature = signed({
  secret: 'secret string',
})
```

Sign url

```ts
const signedUrl = signature.sign('http://example.com/resource')
```

Verify url on resource side

```ts
app.get('/resource', signature.verifier(), (req, res, next) => {
  res.send('ok')
})
```

## Sample application

```ts
import * as express from 'express'
import signed from 'express-signed-url'

// Create signature
const signature = signed({
  secret: 'Xd<dMf72sj;6',
})

const app = express()

// Index with signed link
app.get('/', (req, res, next) => {
  const s = signature.sign('http://localhost:8080/source/a')
  res.send('<a href="' + s + '">' + s + '</a><br/>')
  // It prints something like http://localhost:8080/source/a?signed=r:1422553972;e8d071f5ae64338e3d3ac8ff0bcc583b
})

// Validating
app.get('/source/:a', signature.verifier(), (req, res, next) => {
  res.send(req.params.a)
})

app.listen(8080)
```

## API

Library exports factory which takes _options_ and returns _Signature object_.

```ts
function(options: SignatureOptions): Signature;
```

```ts
type SignatureOptions = {
  secret: string
  ttl?: number
}
```

Example

```ts
import signed from 'express-signed-url'
const signature = signed({
  // secret is required param
  secret: 'secret string',

  // optional. default ttl of signed urls will be 60 sec
  ttl: 60,
})
```

### signature.sign

This method signs url and returns signed one. You also may pass additional object _options_.

```ts
signature.sign(url: string, options?: SignMethodOptions): string;
```

```ts
type SignMethodOptions = {
  method?: string | string[]
  ttl?: number
  exp?: number
  addr?: string
}
```

Example

```js
const signedUrl = signature.sign('http://example.com/resource', {
  // if specified, only this method will be allowed
  // may be string of few methods separated by comma, or array of strings
  method: 'get',

  // time to live for url, started from now
  ttl: 50,

  // expiration timestamp (if ttl isn't specified)
  exp: 1374269431,

  // if set, only request from this address will be allowed
  addr: '::ffff:127.0.0.1',
})
```

### signature.verifier

Return express middleware for validate incoming requests.

```ts
signature.verifier(options?: VerifierMethodOptions): express.RequestHandler;
```

```ts
type VerifierMethodOptions = {
  blackholed?: RequestHandler
  expired?: RequestHandler
  addressReader?: AddressReader
}
```

Example

```ts
app.get(
  '/resource',
  signature.verifier({
    // if specified, this middleware will be called when request isn't valid
    // by default, following error will be thrown
    blackholed: (req, res, next) => {
      const err = new Error('Blackholed')
      ;(err as any).status = 403
      next(err)
    },

    // if specified, this middleware will be called if request is valid, but it's been expired
    // by default, following error will be thrown
    expired: (req, res, next) => {
      const err = new Error('Expired')
      ;(err as any).status = 410
      next(err)
    },

    // if specified, this method will be used to retrieve address of remote client
    // by default, following method will be used
    addressReader: (req) => req.connection.remoteAddress,
  }),
  (req, res, next) => {
    res.send('hello')
  },
)
```

## License

MIT
