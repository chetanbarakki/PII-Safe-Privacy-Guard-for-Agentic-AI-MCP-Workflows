/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#f2efe9",
        ink: "#1c1c1c",
        card: "#fffdf8",
        accent: "#0f766e",
        warn: "#b91c1c",
        pseudo: "#a16207",
      },
      boxShadow: {
        panel: "0 10px 28px rgba(22, 22, 22, 0.11)",
      },
      borderRadius: {
        xl2: "1.1rem",
      },
    },
  },
  plugins: [],
};
