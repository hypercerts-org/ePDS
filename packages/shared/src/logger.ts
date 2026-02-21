import pino from 'pino'

const LOG_LEVEL =
  process.env.LOG_LEVEL ||
  (process.env.NODE_ENV === 'development' ? 'debug' : 'info')

export function createLogger(name: string): pino.Logger {
  return pino({
    name,
    level: LOG_LEVEL,
    ...(process.env.NODE_ENV === 'development'
      ? {
          transport: { target: 'pino/file', options: { destination: 1 } },
          formatters: { level: (label: string) => ({ level: label }) },
        }
      : {}),
  })
}
