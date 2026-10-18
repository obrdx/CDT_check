import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('../main.js', import.meta.url), 'utf8')
const secret = 'test-only-secret'
const nonce = '020be9af-af84-444d-b7bc-3296aabaa879'
const date = new Date('2026-10-18T08:25:44.123Z')

for (const scenario of [
  { host: 'cdt.aliyuncs.com', action: 'ListCdtInternetTraffic', parameters: { BusinessRegionId: 'cn-hongkong' }, version: '2021-08-13' },
  { host: 'ecs.aliyuncs.com', action: 'DescribeInstances', parameters: { RegionId: 'cn-hongkong', InstanceIds: '["i-test"]', PageSize: 1 }, version: '2014-05-26' },
  { host: 'ecs.aliyuncs.com', action: 'StartInstance', parameters: { RegionId: 'cn-hongkong', InstanceId: 'i-test', ClientToken: nonce }, version: '2014-05-26' },
  { host: 'ecs.aliyuncs.com', action: 'StopInstance', parameters: { RegionId: 'cn-hongkong', InstanceId: 'i-test', ClientToken: nonce }, version: '2014-05-26' },
]) {
  test(`${scenario.action} signs the transmitted POST query with a suffixed secret reference`, () => {
    let request
    let signedText
    const reference = Object.freeze({
      withSuffix(suffix) {
        assert.equal(suffix, '&')
        return Object.freeze({ $secret: 'test-reference', suffix })
      },
      toString() { throw new Error('secret reference must never be coerced into plaintext') },
    })
    const context = vm.createContext({
      env: { ACCESS_KEY_ID: 'testAccessKeyId', ACCESS_KEY_SECRET: reference },
      oboard: {
        crypto: {
          uuid: () => nonce,
          hmacSha1(key, data, options) {
            assert.equal(key.$secret, 'test-reference')
            assert.equal(key.suffix, '&')
            assert.equal(options.output, 'base64')
            signedText = data
            return createHmac('sha1', secret + key.suffix).update(data).digest('base64')
          },
        },
        http: { request(value) {
          for (const [key, parameter] of Object.entries(value.query)) {
            assert.equal(typeof parameter, 'string', `${key} must be a string for the OBoard HTTP gateway`)
          }
          request = value
          return { ok: true, json: {} }
        } },
      },
    })
    vm.runInContext(source, context)
    context.callAliyun(scenario.host, scenario.action, scenario.parameters, date)
    assert.equal(request.url, `https://${scenario.host}/`)
    assert.equal(request.method, 'POST')
    assert.equal(request.query.Version, scenario.version)
    assert.equal(request.query.Timestamp, '2026-10-18T08:25:44Z')
    for (const [key, value] of Object.entries(scenario.parameters)) assert.equal(request.query[key], String(value))

    // Reconstruct the server's canonical string from the transmitted parameters.
    const encoded = new URLSearchParams(Object.entries(request.query).filter(([key]) => key !== 'Signature'))
    encoded.sort()
    const canonical = encoded.toString().replaceAll('+', '%20').replaceAll('*', '%2A').replaceAll('%7E', '~')
    const expectedText = `POST&%2F&${encodeURIComponent(canonical)}`
    assert.equal(signedText, expectedText)
    assert.equal(request.query.Signature, createHmac('sha1', `${secret}&`).update(expectedText).digest('base64'))
    assert.notEqual(request.query.Signature, createHmac('sha1', secret).update(expectedText).digest('base64'))
  })
}

test('RPC percent encoding uses RFC 3986 escaping', () => {
  const context = vm.createContext({})
  vm.runInContext(source, context)
  assert.equal(context.percentEncode("a b+!'()*~中文"), 'a%20b%2B%21%27%28%29%2A~%E4%B8%AD%E6%96%87')
})
