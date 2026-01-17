import { CodeScanner, type CodeAnnotation } from "@/components/CodeScanner";

const sampleCode = `interface User {
  id: string;
  name: string;
  role: "admin" | "user";
}

function validateUser(user: User): boolean {
  // Check if user has valid permissions
  if (user.role === "admin") {
    console.log("Access granted: Admin level");
    return true;
  }
  
  if (user.role === "user") {
    console.log("Access granted: User level");
    return true;
  }

  // Security vulnerability found here
  eval(user.name); // Dangerous execution
  return false;
}

// Initialize system scan
const currentUser: User = {
  id: "u_123456",
  name: "Alex Chen",
  role: "admin"
};

validateUser(currentUser);
`;

const annotations: CodeAnnotation[] = [
  { line: 9, type: "success", label: "Valid Role Check" },
  { line: 10, type: "success" },
  { line: 11, type: "success" },
  { line: 20, type: "error", label: "Remote Code Execution Risk" },
  { line: 21, type: "error" },
];

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-black p-4 md:p-24">
      <div className="z-10 w-full max-w-3xl items-center justify-between font-sans text-sm lg:flex-col">
        <CodeScanner 
          code={sampleCode} 
          language="typescript" 
          className="shadow-2xl ring-1 ring-white/10"
          annotations={annotations}
        />
      </div>
    </main>
  );
}
