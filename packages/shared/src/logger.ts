import pino from 'pino'

function defaultLogLevel(): string {
  switch (process.env.NODE_ENV) {
    case 'development':
      return 'debug'
    case 'test':
      return 'silent'
    default:
      return 'info'
  }
}

const LOG_LEVEL = process.env.LOG_LEVEL || defaultLogLevel()

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
