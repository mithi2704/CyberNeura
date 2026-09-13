/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "var(--cyber-border)",
        input: "var(--cyber-input)",
        ring: "var(--ring)",
        background: "var(--background)",
        foreground: "var(--foreground)",
        primary: {
          DEFAULT: "#00d4ff",
          foreground: "#050814",
        },
        secondary: {
          DEFAULT: "#7c3aed",
          foreground: "var(--foreground)",
        },
        destructive: {
          DEFAULT: "#ef4444",
          foreground: "var(--foreground)",
        },
        muted: {
          DEFAULT: "var(--cyber-dark)",
          foreground: "var(--cyber-muted)",
        },
        accent: {
          DEFAULT: "#7c3aed",
          foreground: "var(--foreground)",
        },
        popover: {
          DEFAULT: "var(--popover)",
          foreground: "var(--popover-foreground)",
        },
        card: {
          DEFAULT: "var(--cyber-card)",
          foreground: "var(--foreground)",
        },
        // Cyber theme additions
        cyber: {
          navy: "#0a0f24",
          dark: "var(--cyber-dark)",
          bg: "var(--cyber-bg)",
          card: "var(--cyber-card)",
          'card-border': "var(--cyber-card-border)",
          text: "var(--cyber-text)",
          muted: "var(--cyber-muted)",
          border: "var(--cyber-border)",
          input: "var(--cyber-input)",
          inner: "var(--cyber-inner)",
          'inner-border': "var(--cyber-inner-border)",
          sidebar: "var(--cyber-sidebar)",
          blue: "#00d4ff",
          purple: "#7c3aed",
          pink: "#ff007f",
          green: "#10b981",
          yellow: "#f59e0b",
          red: "#ef4444",
          gray: "#1f2937",
        },
      },
      borderRadius: {
        lg: "0.75rem",
        md: "0.5rem",
        sm: "0.25rem",
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        cyber: ["Inter", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 15px rgba(0, 212, 255, 0.4)",
        "glow-purple": "0 0 15px rgba(124, 58, 237, 0.4)",
        "glow-pink": "0 0 15px rgba(255, 0, 127, 0.4)",
        glass: "0 8px 32px 0 rgba(0, 0, 0, 0.37)",
      },
      backgroundImage: {
        "cyber-gradient": "linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)",
        "cyber-glow-gradient": "linear-gradient(180deg, rgba(0, 212, 255, 0.15) 0%, rgba(124, 58, 237, 0.05) 100%)",
        "card-gradient": "linear-gradient(180deg, rgba(17, 24, 39, 0.8) 0%, rgba(13, 21, 37, 0.8) 100%)",
      },
    },
  },
  plugins: [],
}
