/** Inline SVG key icon used as the app logo. */
export function AppLogo({
  size = 48,
  logoBg,
}: {
  size?: number
  logoBg?: string
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect width="48" height="48" rx="12" fill={logoBg ?? '#2563eb'} />
      <path
        d="M24 14a6 6 0 0 0-1 11.92V30h-3a1 1 0 1 0 0 2h3v2a1 1 0 1 0 2 0v-2h1a1 1 0 1 0 0-2h-1v-4.08A6 6 0 0 0 24 14zm0 2a4 4 0 1 1 0 8 4 4 0 0 1 0-8z"
        fill="white"
      />
    </svg>
  )
}
