import React from "react";
import { Button } from "@/shared/components";
import { AssessmentCard } from "../components/AssessmentCard";

export const AssessmentsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Security Assessments</h1>
          <p className="text-sm text-slate-500">
            Manage comprehensive security audit cycles and vulnerability tests.
          </p>
        </div>
        <Button>+ New Assessment Cycle</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        <AssessmentCard
          id="1"
          name="Web Application Security Audit 2026-Q1"
          target="OWASP Juice Shop"
          status="in_progress"
        />
        <AssessmentCard
          id="2"
          name="Network Reconnaissance & Port Analysis"
          target="OWASP Juice Shop"
          status="completed"
        />
      </div>
    </div>
  );
};
