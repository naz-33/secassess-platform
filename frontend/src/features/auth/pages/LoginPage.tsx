import React from "react";
import { Card } from "@/shared/components";
import { LoginForm } from "../components/LoginForm";

export const LoginPage: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 p-4">
      <Card title="SecAssess Platform Login" subtitle="Access vulnerability analysis workspace" className="max-w-md w-full">
        <LoginForm />
      </Card>
    </div>
  );
};
