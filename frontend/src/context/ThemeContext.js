import { createContext, useContext, useState, useEffect } from "react";

// Theme definitions
export const themes = {
  light: {
    name: "light",
    // Sidebar
    sidebarBg: "#0F172A",
    sidebarText: "#F1F5F9",
    sidebarTextMuted: "#64748B",
    sidebarBorder: "#1E293B",
    sidebarSection: "#334155",

    // Main content
    mainBg: "#F8FAFC",
    mainBgAlt: "#FFFFFF",
    cardBg: "#FFFFFF",
    cardBorder: "#E2E8F0",
    cardBorderHover: "#CBD5E1",

    // Text
    textPrimary: "#1E293B",
    textSecondary: "#475569",
    textMuted: "#94A3B8",

    // Accents
    accent: "#A32D2D",
    accentHover: "#8B2626",
    accentLight: "#FEE2E2",

    // Status colors
    success: "#16A34A",
    successBg: "#DCFCE7",
    warning: "#CA8A04",
    warningBg: "#FEF9C3",
    error: "#DC2626",
    errorBg: "#FEE2E2",
    info: "#2563EB",
    infoBg: "#DBEAFE",

    // Inputs
    inputBg: "#FFFFFF",
    inputBorder: "#CBD5E1",
    inputFocus: "#A32D2D",

    // Shadows
    shadow: "0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06)",
    shadowLg: "0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05)",

    // Database indicators
    mongoDB: "#00ED64",
    redis: "#DC382D",
    neo4j: "#008CC1",
  },
  dark: {
    name: "dark",
    // Sidebar
    sidebarBg: "#0A0F1A",
    sidebarText: "#E2E8F0",
    sidebarTextMuted: "#64748B",
    sidebarBorder: "#1E293B",
    sidebarSection: "#475569",

    // Main content
    mainBg: "#0F172A",
    mainBgAlt: "#1E293B",
    cardBg: "#1E293B",
    cardBorder: "#334155",
    cardBorderHover: "#475569",

    // Text
    textPrimary: "#F1F5F9",
    textSecondary: "#CBD5E1",
    textMuted: "#64748B",

    // Accents
    accent: "#EF4444",
    accentHover: "#DC2626",
    accentLight: "#450A0A",

    // Status colors
    success: "#22C55E",
    successBg: "#14532D",
    warning: "#EAB308",
    warningBg: "#422006",
    error: "#EF4444",
    errorBg: "#450A0A",
    info: "#3B82F6",
    infoBg: "#1E3A5F",

    // Inputs
    inputBg: "#1E293B",
    inputBorder: "#475569",
    inputFocus: "#EF4444",

    // Shadows
    shadow: "0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.3)",
    shadowLg: "0 10px 15px -3px rgba(0,0,0,0.5), 0 4px 6px -2px rgba(0,0,0,0.4)",

    // Database indicators
    mongoDB: "#00ED64",
    redis: "#FF6B6B",
    neo4j: "#4FC3F7",
  },
};

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [isDark, setIsDark] = useState(() => {
    // Check localStorage for saved preference
    const saved = localStorage.getItem("cti-theme");
    if (saved) return saved === "dark";
    // Check system preference
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  const theme = isDark ? themes.dark : themes.light;

  const toggleTheme = () => {
    setIsDark((prev) => {
      const newValue = !prev;
      localStorage.setItem("cti-theme", newValue ? "dark" : "light");
      return newValue;
    });
  };

  useEffect(() => {
    // Update body background for smooth transitions
    document.body.style.background = theme.mainBg;
    document.body.style.transition = "background 0.3s ease";
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, isDark, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}
