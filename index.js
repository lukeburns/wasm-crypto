/* global WebAssembly */

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const loader = require('assemblyscript/lib/loader')
const bufferFrom = require('buffer-from')
const bufferAlloc = require('buffer-alloc-unsafe')

const load = () => {
  const heapSize = 65536 * 4096
  const pages = ((heapSize + 0xffff) & ~0xffff) >>> 16
  const imports = {
    'env': {
      memory: new WebAssembly.Memory({
        initial: pages
      })
    }
  }
  return loader.instantiateBuffer(fs.readFileSync(path.resolve(__dirname, './build/optimized.wasm')), imports)
}

const SECRETKEY_BYTES = 32
const PUBLICKEY_BYTES = 32
const SIGN_BYTES = 64

const wasm = load()
const uintid = wasm.Uint8Array_ID
const _empty = wasm.__retain(wasm.__allocArray(uintid, []))

function __retainKeyPair (secretKey) {
  if (secretKey && (!Buffer.isBuffer(secretKey) || secretKey.length !== SECRETKEY_BYTES)) {
    return new Error('Secret key should be a 32-byte Uint8Array')
  }

  if (!secretKey) {
    secretKey = bufferAlloc(SECRETKEY_BYTES)
    secretKey.set(crypto.randomBytes(SECRETKEY_BYTES))
  }

  let _secretKey = wasm.__retain(wasm.__allocArray(uintid, secretKey))
  let _keyPair = wasm.signKeypairFromSeed(_secretKey)
  let _publicKey = wasm.signPublicKey(_keyPair)
  return {
    _secretKey,
    _publicKey,
    _keyPair
  }
}

function __releaseKeyPair ({ _secretKey, _publicKey, _keyPair }) {
  wasm.__release(_secretKey)
  wasm.__release(_publicKey)
  wasm.__release(_keyPair)
}

function keyPair (secretKey) {
  if (secretKey && (!Buffer.isBuffer(secretKey) || secretKey.length !== SECRETKEY_BYTES)) {
    return new Error(`Secret key should be a ${SECRETKEY_BYTES}-byte Uint8Array`)
  }

  if (!secretKey) {
    secretKey = bufferAlloc(SECRETKEY_BYTES)
    secretKey.set(crypto.randomBytes(SECRETKEY_BYTES))
  }

  const __kp = __retainKeyPair(secretKey)
  const publicKey = bufferFrom(wasm.__getArray(__kp._publicKey))

  __releaseKeyPair(__kp)

  return {
    secretKey,
    publicKey
  }
}

function sign (message, secretKey) {
  if (!message || !Buffer.isBuffer(message)) {
    return new Error(`Message should be Uint8Array`)
  }

  if (!secretKey || !Buffer.isBuffer(secretKey) || secretKey.length !== SECRETKEY_BYTES) {
    return new Error(`Secret key should be a ${SECRETKEY_BYTES}-byte Uint8Array`)
  }

  const _message = wasm.__retain(wasm.__allocArray(uintid, message))

  const __kp = __retainKeyPair(secretKey)

  const _signature = wasm.sign(_message, __kp._keyPair)

  const signature = bufferFrom(wasm.__getArray(_signature))

  wasm.__release(_message)
  wasm.__release(_signature)
  __releaseKeyPair(__kp)

  return signature
}

function verify (message, signature, publicKey) {
  if (!message || !Buffer.isBuffer(message)) {
    return new Error(`Message should be Uint8Array`)
  }

  if (!signature || !Buffer.isBuffer(signature) || signature.length !== SIGN_BYTES) {
    return new Error(`Signature should be ${SIGN_BYTES}-byte Uint8Array`)
  }

  if (!publicKey || !Buffer.isBuffer(publicKey) || publicKey.length !== PUBLICKEY_BYTES) {
    return new Error(`Public key should be ${PUBLICKEY_BYTES}-byte Uint8Array`)
  }

  const _message = wasm.__retain(wasm.__allocArray(uintid, message))
  const _signature = wasm.__retain(wasm.__allocArray(uintid, signature))
  const _publicKey = wasm.__retain(wasm.__allocArray(uintid, publicKey))

  const verification = !!wasm.signVerify(_signature, _message, _publicKey)

  wasm.__release(_message)
  wasm.__release(_signature)
  wasm.__release(_publicKey)

  return verification
}

module.exports = {
  keyPair,
  sign,
  verify
}
