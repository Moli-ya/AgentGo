import { startLocalBenchmarkFixture } from './local-fixture'

const fixture = await startLocalBenchmarkFixture()
console.log(
  JSON.stringify({
    status: 'ready',
    version: fixture.version,
    baseUrl: fixture.baseUrl
  })
)

await new Promise<void>((resolve, reject) => {
  let closing = false
  const close = (): void => {
    if (closing) return
    closing = true
    void fixture.close().then(resolve, reject)
  }
  process.once('SIGINT', close)
  process.once('SIGTERM', close)
})
