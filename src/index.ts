export * from './types.js'
import { URLSearchParams } from 'url'
import { createHash } from 'crypto'
import { Request, RequestHandler } from 'express'
import { HashAlgorithm, SignatureOptions, SignMethodOptions } from './index.js'
import { AddressReader, VerifierMethodOptions, VerifyResult } from './types.js'

const lengthOfHash: Record<HashAlgorithm, number> = {
  md5: 128 / 4,
  sha256: 256 / 4,
}

const signatureDataKeys = ['e', 'a', 'r', 'm'] as const
type SignatureData = Partial<Record<typeof signatureDataKeys[number], string>>

class Signature implements Signature {
  private secret: string
  private ttl: number
  private hashAlgo: HashAlgorithm

  constructor(options: SignatureOptions) {
    this.secret = options.secret
    this.ttl = options.ttl || 60
    this.hashAlgo = options.hashAlgo || 'sha256'
  }

  stringify(data: SignatureData): string {
    return new URLSearchParams(data)
      .toString()
      .replace(/=/g, ':')
      .replace(/&/g, ';')
  }

  parse(url: string): SignatureData {
    const params = new URLSearchParams(
      url.replace(/:/g, '=').replace(/;/g, '&'),
    )
    const data = {} as SignatureData
    for (const k of signatureDataKeys) {
      data[k] = params.get(k) ?? undefined
    }
    return data
  }

  sign(url: string, options: SignMethodOptions = {}): string {
    const data: SignatureData = {
      r: Math.floor(Math.random() * 10000000000).toString(),
    }

    const exp =
      (options.ttl ? Math.ceil(+new Date() / 1000) + options.ttl : null) ||
      options.exp ||
      (this.ttl ? Math.ceil(+new Date() / 1000) + this.ttl : null)
    if (exp) {
      data.e = exp.toString()
    }
    if (options.addr) {
      data.a = options.addr
    }

    if (options.method) {
      data.m = (
        Array.isArray(options.method)
          ? options.method.join(',')
          : options.method
      ).toUpperCase()
    }

    url +=
      (url.indexOf('?') == -1 ? '?' : '&') +
      'signed=' +
      this.stringify(data) +
      ';'

    const hash = createHash(this.hashAlgo)
    hash.update(url, 'utf8')
    hash.update(this.secret[0])
    url += hash.digest('hex')

    return url
  }

  verifyString(str: string, sign: string): boolean {
    for (let i = 0; i < this.secret.length; i++) {
      const hash = createHash(this.hashAlgo)
      hash.update(str, 'utf8')
      hash.update(this.secret[i], 'utf8')
      if (hash.digest('hex') == sign) return true
    }
    return false
  }

  verifyUrl(req: Request, addressReader?: AddressReader): VerifyResult {
    const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`

    if (
      url.length < lengthOfHash[this.hashAlgo] + 1 ||
      !this.verifyString(
        url.substring(0, url.length - lengthOfHash[this.hashAlgo]),
        url.substr(-1 * lengthOfHash[this.hashAlgo]),
      )
    ) {
      return VerifyResult.blackholed
    }

    // get signed data
    let lastAmpPos = url.lastIndexOf('&signed=')
    if (lastAmpPos == -1) {
      lastAmpPos = url.lastIndexOf('?signed=')
    }
    if (lastAmpPos == -1) {
      return VerifyResult.blackholed
    }
    const data = this.parse(
      url.substring(
        lastAmpPos + 8,
        url.length - lengthOfHash[this.hashAlgo] - 1,
      ),
    )
    req.url = url.substring(0, lastAmpPos)

    // check additional conditions
    if (data.a && addressReader && data.a != addressReader(req)) {
      return VerifyResult.blackholed
    }
    if (data.m && data.m.indexOf(req.method) == -1) {
      return VerifyResult.blackholed
    }
    if (data.e && parseInt(data.e as string) < Math.ceil(+new Date() / 1000)) {
      return VerifyResult.expired
    }
    return VerifyResult.ok
  }

  verifier({
    blackholed = (req, res, next) => {
      const err = new Error('Blackholed')
      ;(err as any).status = 403
      next(err)
    },
    expired = (req, res, next) => {
      const err = new Error('Expired')
      ;(err as any).status = 410
      next(err)
    },
    addressReader = (req) => req.ip,
  }: VerifierMethodOptions = {}): RequestHandler {
    return (req, res, next) => {
      switch (this.verifyUrl(req, addressReader)) {
        case VerifyResult.ok:
          next()
          break
        case VerifyResult.blackholed:
          return blackholed(req, res, next)
        case VerifyResult.expired:
          return expired(req, res, next)
      }
    }
  }
}

export default function (options: SignatureOptions) {
  return new Signature(options)
}
