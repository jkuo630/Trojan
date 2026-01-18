import { VulnerabilityCard } from "@/components/Vulnerability";

export default function TestingPage() {
  return (
    <div>
      <VulnerabilityCard
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