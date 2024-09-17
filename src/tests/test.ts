import express from 'express'
import http from 'http'
import got, { HTTPError } from 'got'
import signed, { HashAlgorithm, Signature } from '../index.js'

const TEST_PORT = 23001

async function makeRequest(
  path: string,
  { expectedCode = 200 } = {},
): Promise<string> {
  try {
    return await got.get(path, { resolveBodyOnly: true })
  } catch (error) {
    if (error instanceof HTTPError && error.response.statusCode === expectedCode) {
      return error.response.body
    } else throw error
  }
}

const algos: HashAlgorithm[] = ['sha256', 'md5']
algos.forEach((algo, i) => {
  const port = TEST_PORT + i
  let localIp: string | undefined

  describe(`test ${algo} hash`, function () {
    this.timeout(10000)

    let signature: Signature, app: express.Express, server: http.Server

    before('should create signature', () => {
      signature = signed({
        // secret: crypto.randomBytes(20).toString('hex'),
        secret: 'Xd<dMf72sj;6',
        hashAlgo: algo,
      })
    })

    before('should start server and determine own ip', async () => {
      app = express()

      app.get('/ip', function (req, res) {
        localIp = req.ip
        res.send('ok')
      })

      app.get('/try', signature.verifier(), function (_req, res) {
        res.send('ok')
      })

      const v1 = express.Router()
      v1.get('/try', signature.verifier(), (_, res) => res.send('ok'))
      app.use('/v1', v1)

      await new Promise<void>((resolve) => {
        server = app.listen(port, () => {
          resolve()
        })
      })

      await makeRequest(`http://localhost:${port}/ip`)
    })

    it('should be 200', async () => {
      await makeRequest(signature.sign(`http://localhost:${port}/try`))
    })

    it('should be 200 (with baseUrl)', async () => {
      await makeRequest(signature.sign(`http://localhost:${port}/v1/try`))
    })

    it('should be 200 (address check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          addr: localIp,
        }),
      )
    })

    it('should be 200 (method check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          method: 'get,post',
        }),
      )
    })

    it('should be 200 (ttl check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          ttl: 5,
        }),
      )
    })

    it('should be 200 (expiration check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          exp: Date.now() + 5000,
        }),
      )
    })

    it('should be 403 (bad token)', async () => {
      await makeRequest(signature.sign(`http://localhost:${port}/try`) + '1', {
        expectedCode: 403,
      })
    })

    it('should be 403 (address check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          addr: '127.0.0.2',
        }),
        {
          expectedCode: 403,
        },
      )
    })

    it('should be 403 (method check)', async () => {
      await makeRequest(
        signature.sign(`http://localhost:${port}/try`, {
          method: 'post,delete',
        }),
        {
          expectedCode: 403,
        },
      )
    })

    it('should be 410 (ttl check)', async () => {
      const link = signature.sign(`http://localhost:${port}/try`, {
        ttl: 1,
      })
      await new Promise((resolve) => setTimeout(resolve, 2000))
      await makeRequest(link, { expectedCode: 410 })
    })

    it('should be 410 (expiration check)', async () => {
      const link = signature.sign(`http://localhost:${port}/try`, {
        exp: Math.floor(Date.now() / 1000),
      })
      await new Promise((resolve) => setTimeout(resolve, 2000))
      await makeRequest(link, { expectedCode: 410 })
    })

    after('should stop server', async () => {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      })
    })
  })
})
