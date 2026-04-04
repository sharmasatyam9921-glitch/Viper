import { SVGProps } from 'react'

interface StealthIconProps extends SVGProps<SVGSVGElement> {
  size?: number
}

export function StealthIcon({ size = 24, ...props }: StealthIconProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 800 600"
      fill="currentColor"
      {...props}
    >
      <polygon points="400,80 800,420 720,420 680,380 620,420 560,380 500,420 440,380 380,420 320,380 260,420 200,380 120,420 0,420" />
    </svg>
  )
}
