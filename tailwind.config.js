/** @type {import('tailwindcss').Config} */
const config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        aase: {
          base: '#080C0A',
          surface: '#0D1410',
          surface2: '#111A16',
          border: 'rgba(0, 230, 118, 0.12)',
          accent: '#00E676',
          accentDim: 'rgba(0, 230, 118, 0.08)',
          text: '#E8F5E9',
          muted: '#5A7A65',
          dim: '#2E4A38',
          red: '#FF4F4F',
          orange: '#FF8C42',
          yellow: '#FFD166',
          blue: '#4FC3F7',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['DM Sans', 'sans-serif'],
      },
      animation: {
        blink: 'blink 1s step-end infinite',
        float: 'float 4s ease-in-out infinite',
        scan: 'scanDown 3s linear infinite',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'fade-in-up': 'fadeInUp 0.6s cubic-bezier(0.4, 0, 0.2, 1) forwards',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
        scanDown: {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(0, 230, 118, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(0, 230, 118, 0.7)' },
        },
        fadeInUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'grid-pattern':
          'linear-gradient(rgba(0, 230, 118, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 230, 118, 0.03) 1px, transparent 1px)',
      },
      backgroundSize: {
        grid: '40px 40px',
      },
    },
  },
  plugins: [],
};

export default config;
