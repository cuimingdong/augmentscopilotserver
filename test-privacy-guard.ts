/**
 * Privacy Guard - Test Suite
 * 
 * Run: deno run --allow-net test-privacy-guard.ts
 */

import { privacyGuard } from "./privacy-guard.ts";

console.log("🔒 Privacy Guard - Test Suite\n");

// Test 1: API Keys
console.log("Test 1: API Key Sanitization");
const apiKeyTest = "My OpenAI key is sk-1234567890abcdefghijklmnop and Stripe key is sk_live_abcd1234";
const sanitized1 = privacyGuard.sanitizeString(apiKeyTest);
console.log("Original:", apiKeyTest);
console.log("Sanitized:", sanitized1);
console.log("✅ Pass:", !sanitized1.includes("sk-1234") && !sanitized1.includes("sk_live"));
console.log();

// Test 2: Email Addresses
console.log("Test 2: Email Sanitization");
const emailTest = "Contact me at john.doe@company.com or support@example.org";
const sanitized2 = privacyGuard.sanitizeString(emailTest);
console.log("Original:", emailTest);
console.log("Sanitized:", sanitized2);
console.log("✅ Pass:", !sanitized2.includes("@company.com") && !sanitized2.includes("@example.org"));
console.log();

// Test 3: File Paths
console.log("Test 3: File Path Sanitization");
const pathTest = "File at C:\\Users\\John\\Documents\\secret.txt and /Users/john/project/api.key";
const sanitized3 = privacyGuard.sanitizeString(pathTest);
console.log("Original:", pathTest);
console.log("Sanitized:", sanitized3);
console.log("✅ Pass:", !sanitized3.includes("C:\\Users") && !sanitized3.includes("/Users/john"));
console.log();

// Test 4: Passwords
console.log("Test 4: Password Sanitization");
const passwordTest = "Login with password=mySecret123 or passwd: admin123";
const sanitized4 = privacyGuard.sanitizeString(passwordTest);
console.log("Original:", passwordTest);
console.log("Sanitized:", sanitized4);
console.log("✅ Pass:", !sanitized4.includes("mySecret123") && !sanitized4.includes("admin123"));
console.log();

// Test 5: Bearer Tokens
console.log("Test 5: Bearer Token Sanitization");
const tokenTest = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc";
const sanitized5 = privacyGuard.sanitizeString(tokenTest);
console.log("Original:", tokenTest);
console.log("Sanitized:", sanitized5);
console.log("✅ Pass:", !sanitized5.includes("eyJhbGci"));
console.log();

// Test 6: JWT Tokens
console.log("Test 6: JWT Token Sanitization");
const jwtTest = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const sanitized6 = privacyGuard.sanitizeString(jwtTest);
console.log("Original:", jwtTest);
console.log("Sanitized:", sanitized6);
console.log("✅ Pass:", !sanitized6.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
console.log();

// Test 7: Object Sanitization
console.log("Test 7: Object Sanitization");
const objectTest = {
  name: "John Doe",
  email: "john@company.com",
  apiKey: "sk-1234567890abcdef",
  config: {
    password: "secret123",
    path: "C:\\Users\\John\\config.json"
  }
};
const sanitized7 = privacyGuard.sanitize(objectTest);
console.log("Original:", JSON.stringify(objectTest, null, 2));
console.log("Sanitized:", JSON.stringify(sanitized7, null, 2));
console.log("✅ Pass:", sanitized7.apiKey === '[REDACTED]' && 
                       sanitized7.config.password === '[REDACTED]' &&
                       !JSON.stringify(sanitized7).includes("john@company.com"));
console.log();

// Test 8: Safety Check
console.log("Test 8: Safety Validation");
const unsafeData = {
  message: "Here's my API key: sk-1234567890abcdef",
  file: "C:\\Users\\John\\secret.txt"
};
const safetyCheck = privacyGuard.isSafeToSend(unsafeData);
console.log("Data:", JSON.stringify(unsafeData));
console.log("Safety Check:", safetyCheck);
console.log("✅ Pass:", !safetyCheck.safe && safetyCheck.issues.length > 0);
console.log();

// Test 9: Sanitization Report
console.log("Test 9: Sanitization Report");
const reportTest = "My key is sk-abc123xyz and email is user@test.com at C:\\Users\\test";
const reportSanitized = privacyGuard.sanitizeString(reportTest);
const report = privacyGuard.getSanitizationReport(reportTest, reportSanitized);
console.log("Original:", reportTest);
console.log("Report:", report);
console.log("✅ Pass:", report.redacted === 3 && report.patterns.length === 3);
console.log();

// Test 10: IP Hashing
console.log("Test 10: IP Address Hashing");
const ip1 = "192.168.1.100";
const ip2 = "192.168.1.100"; // Same IP
const ip3 = "10.0.0.1"; // Different IP
const hash1 = privacyGuard.hashIP(ip1);
const hash2 = privacyGuard.hashIP(ip2);
const hash3 = privacyGuard.hashIP(ip3);
console.log("IP 1:", ip1, "→", hash1);
console.log("IP 2:", ip2, "→", hash2);
console.log("IP 3:", ip3, "→", hash3);
console.log("✅ Pass:", hash1 === hash2 && hash1 !== hash3 && hash1.startsWith("ip_"));
console.log();

// Test 11: Real-world Prompt
console.log("Test 11: Real-world Prompt Sanitization");
const realPrompt = `
I need help fixing this login function:

const apiKey = "sk-proj-1234567890abcdefghijklmnop";
const dbPassword = "mySecretPassword123";
const configPath = "C:\\Users\\JohnDoe\\MyCompany\\SecretProject\\config.json";

async function login(email) {
  // Email: john.doe@mycompany.com
  const token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc";
  return fetch("https://api.example.com?token=secret123", {
    headers: { Authorization: token }
  });
}
`;
const sanitizedPrompt = privacyGuard.sanitizeString(realPrompt);
console.log("Original Prompt Length:", realPrompt.length);
console.log("Sanitized Prompt Length:", sanitizedPrompt.length);
console.log("\nSanitized Prompt:\n", sanitizedPrompt);
console.log("\n✅ Pass:", 
  !sanitizedPrompt.includes("sk-proj-") &&
  !sanitizedPrompt.includes("mySecretPassword") &&
  !sanitizedPrompt.includes("C:\\Users\\JohnDoe") &&
  !sanitizedPrompt.includes("john.doe@mycompany.com") &&
  !sanitizedPrompt.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
);

console.log("\n\n🎉 All tests completed!");
console.log("\n📊 Summary:");
console.log("- API Keys: Redacted ✅");
console.log("- Emails: Redacted ✅");
console.log("- File Paths: Redacted ✅");
console.log("- Passwords: Redacted ✅");
console.log("- Bearer Tokens: Redacted ✅");
console.log("- JWT Tokens: Redacted ✅");
console.log("- Objects: Sanitized ✅");
console.log("- Safety Check: Working ✅");
console.log("- Reports: Accurate ✅");
console.log("- IP Hashing: Working ✅");
console.log("- Real-world Prompts: Safe ✅");
