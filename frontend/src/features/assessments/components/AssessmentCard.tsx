import React from "react";
import { Card, Badge, Button } from "@/shared/components";

interface AssessmentCardProps {
  id: string;
  name: string;
  target: string;
  status: "draft" | "in_progress" | "completed" | "archived";
}

export const AssessmentCard: React.FC<AssessmentCardProps> = ({ name, target, status }) => {
  return (
    <Card className="flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-2">
          <Badge variant={status === "in_progress" ? "info" : "neutral"}>{status}</Badge>
          <span className="text-xs text-slate-400">Created by Lead Assessor</span>
        </div>
        <h3 className="text-base font-semibold text-slate-800">{name}</h3>
        <p className="text-xs text-slate-500 mt-1">Target: {target}</p>
      </div>
      <div className="mt-4 pt-3 border-t border-slate-100 flex justify-end">
        <Button size="sm" variant="outline">
          View Assessment
        </Button>
      </div>
    </Card>
  );
};
