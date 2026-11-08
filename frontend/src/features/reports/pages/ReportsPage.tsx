import React from "react";
import { Card, Button } from "@/shared/components";
import { ReportList } from "../components/ReportList";

export const ReportsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Security Assessment Reports</h1>
          <p className="text-sm text-slate-500">
            Generate and export academic and professional security assessment documentation.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline">Export DOCX</Button>
          <Button>Generate PDF Report</Button>
        </div>
      </div>

      <Card title="Generated Assessment Deliverables">
        <ReportList />
      </Card>
    </div>
  );
};
