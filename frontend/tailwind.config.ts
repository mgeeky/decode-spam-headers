import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        background: "#1e1e2e",
        surface: "#282a36",
        text: "#f8f8f2",
        spam: "#ff5555",
        suspicious: "#ffb86c",
        clean: "#50fa7b",
        accent: "#bd93f9",
        info: "#8be9fd",
      },
    },
  },
  plugins: [],
};

export default config;
