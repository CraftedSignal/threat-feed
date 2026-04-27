/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './layouts/**/*.html',
    './content/**/*.{html,md}',
    './assets/js/**/*.js',
  ],
  // Severity classes are constructed at template time (e.g. `bg-sev-{{ $sev }}`),
  // so Tailwind's content scan can't see them — safelist explicitly.
  safelist: [
    'sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-rumour',
    'bg-sev-critical', 'bg-sev-high', 'bg-sev-medium', 'bg-sev-low', 'bg-sev-rumour',
    'text-sev-critical', 'text-sev-high', 'text-sev-medium', 'text-sev-low', 'text-sev-rumour',
    'group-hover:text-sev-critical', 'group-hover:text-sev-high', 'group-hover:text-sev-medium',
    'group-hover:text-sev-low', 'group-hover:text-sev-rumour',
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ['Space Grotesk', 'Inter', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        // Tokens reference CSS variables defined in main.css.
        // Light + dark each set the variable values.
        base: 'rgb(var(--color-base) / <alpha-value>)',
        panel: 'rgb(var(--color-panel) / <alpha-value>)',
        'panel-2': 'rgb(var(--color-panel-2) / <alpha-value>)',
        stroke: 'rgb(var(--color-stroke) / <alpha-value>)',
        accent: 'rgb(var(--color-accent) / <alpha-value>)',
        accent2: 'rgb(var(--color-accent2) / <alpha-value>)',
        muted: 'rgb(var(--color-muted) / <alpha-value>)',
        text: 'rgb(var(--color-text) / <alpha-value>)',
        // Severity scale — same hue across themes, tuned for both backgrounds.
        sev: {
          critical: 'rgb(var(--color-sev-critical) / <alpha-value>)',
          high: 'rgb(var(--color-sev-high) / <alpha-value>)',
          medium: 'rgb(var(--color-sev-medium) / <alpha-value>)',
          low: 'rgb(var(--color-sev-low) / <alpha-value>)',
          rumour: 'rgb(var(--color-sev-rumour) / <alpha-value>)',
        },
      },
      boxShadow: {
        soft: 'var(--shadow-soft)',
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
};
