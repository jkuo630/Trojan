// src/app/testing/mockFindings.ts

import type { VulnerabilityCardData } from "../../components/Vulnerability";


// Mocked backend-style findings based on your screenshot
export const mockFindings: VulnerabilityCardData[] = [
  {
    title: "Unrestricted Input Accepted in Login Form",
    category: "Authorization",
    severity: "low",
    message: "No type/length validation on username; can enable injection/DoS",
    filePath: "/src/pages/assets/Main.jsx",
    line: 197,
  },
  {
    title: "Unrestricted Input Accepted in Login",
    severity: "low",
    message: "No type/length validation on username; can enable injection/DoS",
    filePath: "/src/pages/assets/Main.jsx",
    line: 197,
  },
  {
    title: "Unrestricted Input Accepted in",
    severity: "low",
    message: "No type/length validation on username; can enable injection/DoS",
    filePath: "/src/pages/assets/Main.jsx",
    line: 197,
  },
  {
    title: "Unrestricted Input Accep",
    severity: "low",
    message: "No type/length validation on username; can enable injection/DoS",
    filePath: "/src/pages/assets/Main.jsx",
    line: 197,
  },
];
