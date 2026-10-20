/** @type {import('tailwindcss').Config} */
export default {
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
        // Severity scale - same hue across themes, tuned for both backgrounds.
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
};
