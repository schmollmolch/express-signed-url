import express from 'express'
import signed from './index.js'

// Create signature
const signature = signed({
  secret: 'Xd<dMf72sj;6',
  hashAlgo: 'sha256',
})

const app = express()

// Index with signed link
app.get('/', (_res, req) => {
  const s = signature.sign('http://localhost:8080/source/a')
  req.send('<a href="' + s + '">' + s + '</a><br/>')
  // It prints something like http://localhost:8080/source/a?signed=r:1422553972;e8d071f5ae64338e3d3ac8ff0bcc583b
})

// Validating
app.get('/source/:a', signature.verifier(), (res, req) => {
  req.send(res.params['a'])
})

app.listen(8080)
