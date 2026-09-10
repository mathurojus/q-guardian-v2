/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ── Banking-grade enterprise palette ─────────────────────────────
        navy:     "#0B1F3A",   // primary headings / active nav / large numbers
        midnight: "#07152B",   // darkest surfaces (code windows, chat bubbles)
        cobalt: {
          50:  "#EEF3FE",
          100: "#D9E4FC",
          200: "#B3C9F8",
          300: "#83A7EF",
          400: "#4F7DE2",
          500: "#2F63D9",
          600: "#2457D6",
          700: "#1D48B0",
          800: "#1A3C8C",
          900: "#16306E",
        },
        gold: {
          DEFAULT: "#C6A15B",
          50:  "#FAF6ED",
          100: "#F3E9D6",
          200: "#E7D6AC",
          300: "#D9C07F",
          400: "#CFAF67",
          500: "#C6A15B",
          600: "#A98741",
          700: "#8A6B33",
        },
        critical:  "#D92D20",
        warning:   "#D99000",
        success:   "#168A68",
        // Navy-tinted neutral ramp (page bg, borders, secondary text)
        slate: {
          50:  "#F7F8FA",
          100: "#EEF1F5",
          200: "#E1E6ED",
          300: "#CDD5E0",
          400: "#98A2B3",
          500: "#667085",
          600: "#475467",
          700: "#344054",
          800: "#1D2939",
          900: "#0B1F3A",
          950: "#07152B",
        },
        // Legacy aliases now point at the enterprise palette
        brand: {
          dark:   "#0B1F3A",
          accent: "#2457D6",
          cyan:   "#C6A15B",
          emerald: "#168A68",
          light:  "#F7F8FA",
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      borderRadius: {
        lg: "8px",
        xl: "10px",
        "2xl": "12px",
      },
    },
  },
  plugins: [],
}
