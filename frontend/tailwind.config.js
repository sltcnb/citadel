/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Neutral grayscale — calm slate base, near-AAA contrast in body.
        gray: {
          50:  '#F9FAFB',  // body bg (slightly off-white)
          100: '#F3F4F6',  // chip / row hover
          200: '#EAECEF',  // borders (hairline feel)
          300: '#D1D5DB',  // strong borders / disabled
          400: '#9CA3AF',  // icons only — not for body text
          500: '#6B7280',  // muted text
          600: '#4B5563',  // body emphasis
          700: '#374151',
          800: '#1F2937',
          900: '#111827',
          950: '#030712',
        },
        brand: {
          accent:       '#6366F1',  // soft indigo — pastel-leaning primary
          accenthover:  '#4F46E5',
          accentlight:  '#EEF2FF',
          link:         '#4F46E5',
          linkhover:    '#4338CA',
          text:         '#1F2230',  // softer near-black
          textmuted:    '#6B7280',
          surface:      '#FFFFFF',
          surfacealt:   '#FAF7FB',  // very faint warm tint instead of pure off-white
          border:       '#EAECEF',
          // Legacy aliases
          sidebar:      '#0F172A',
          sidebarmuted: '#9CA3AF',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(15,23,42,0.04)',
        'card-md': '0 1px 2px 0 rgba(15,23,42,0.05), 0 4px 12px -2px rgba(15,23,42,0.06)',
        soft: '0 1px 0 0 rgba(15,23,42,0.03)',
      },
    },
  },
  plugins: [],
}
