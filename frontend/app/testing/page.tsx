import { VulnerabilityPopUp } from "@/components/VulnerabilityPopUp";

export default function TestingPage() {
  return (
    <div>
      <VulnerabilityPopUp
        data={{
          title: "Missing Authentication Checks",
          message: "This endpoint does not verify user authentication before processing requests.",
          severity: "high",
          filePath: "src/api/users.ts",
          line: 42,
        }}
      />
    </div>
  );
}