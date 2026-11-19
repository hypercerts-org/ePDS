import type { AddressInfo } from 'node:net'
import type { Express } from 'express'

export interface TestServer {
  baseUrl: string
  close: () => Promise<void>
}

/** Start `app` on a random loopback port for real-HTTP route tests. */
export async function listenOnLoopback(app: Express): Promise<TestServer> {
  const server = await new Promise<ReturnType<Express['listen']>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => {
      resolve(s)
    })
  })
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      }),
  }
}
