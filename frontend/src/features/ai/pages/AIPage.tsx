import React from "react";
import { AIAnalysisPanel } from "../components/AIAnalysisPanel";

export const AIPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">AI-Assisted Security Intelligence</h1>
        <p className="text-sm text-slate-500">
          Redacted LLM vulnerability interpretations, attack chain prioritization, and remediation guides.
        </p>
      </div>

      <div className="space-y-4">
        <AIAnalysisPanel
          functionType="interpret"
          model="claude-3-5-sonnet"
          content={`Vulnerability Breakdown:
The target application is vulnerable to SQL injection due to dynamic string concatenation in the user authentication query. An attacker can supply a malicious payload in the email parameter to bypass authentication controls and retrieve administrator tokens without valid credentials.`}
        />

        <AIAnalysisPanel
          functionType="remediate"
          model="claude-3-5-sonnet"
          content={`Remediation Guidance:
1. Replace inline SQL concatenation with parameterized prepared statements.
2. In Sequelize/TypeORM or raw SQL, use bind parameters: \`SELECT * FROM Users WHERE email = :email\`.
3. Enforce strict input validation using email schema constraints.`}
        />
      </div>
    </div>
  );
};
