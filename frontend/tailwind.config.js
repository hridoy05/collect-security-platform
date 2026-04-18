/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#000000',
        'risk-red': '#fc4d4d',
        'risk-amber': '#f6ad55',
        'risk-green': '#48bb78',
        'risk-blue': '#63b3ed',
        'risk-purple': '#9f7aea',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Space Mono"', 'ui-monospace', 'monospace'],
        sans: ['"Space Grotesk"', 'ui-sans-serif', 'system-ui'],
      },
      borderRadius: {
        DEFAULT: '6px',
        none: '0px',
        sm: '6px',
        md: '6px',
        lg: '6px',
        xl: '6px',
        full: '9999px',
      },
      letterSpacing: {
        ui: '0.08em',
      },
    },
  },
  plugins: [],
}
