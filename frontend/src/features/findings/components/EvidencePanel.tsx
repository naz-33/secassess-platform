import { useState } from "react";
import { FolderLock, Upload, PlusCircle, ShieldCheck } from "lucide-react";
import { Button } from "../../../components/Button";
import { RequireRole } from "../../../auth/RequireRole";
import { EvidenceItemView } from "./EvidenceItemView";
import { EvidenceUploadModal } from "./EvidenceUploadModal";
import { EvidenceNoteModal } from "./EvidenceNoteModal";
import type { EvidenceRead } from "../../../api/types";

interface EvidencePanelProps {
  findingId: string;
  evidences?: EvidenceRead[];
}

export function EvidencePanel({ findingId, evidences = [] }: EvidencePanelProps) {
  const [uploadOpen, setUploadOpen] = useState(false);
  const [noteOpen, setNoteOpen] = useState(false);

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <FolderLock className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-sm font-bold text-slate-100">
              Supporting Evidence ({evidences.length})
            </h2>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Evidence is append-only and immutable. Original files and outputs cannot be altered or deleted.
          </p>
        </div>

        {/* Assessor actions */}
        <RequireRole roles={["admin", "assessor"]}>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setNoteOpen(true)}
              className="text-xs h-8 gap-1.5"
            >
              <PlusCircle className="h-3.5 w-3.5 mr-1" />
              <span>Add Note</span>
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={() => setUploadOpen(true)}
              className="text-xs h-8 gap-1.5"
            >
              <Upload className="h-3.5 w-3.5 mr-1" />
              <span>Upload Evidence</span>
            </Button>
          </div>
        </RequireRole>
      </div>

      {/* Evidence list */}
      {evidences.length === 0 ? (
        <div className="rounded border border-slate-800/80 bg-slate-950/40 p-6 text-center">
          <ShieldCheck className="h-8 w-8 text-slate-500 mx-auto mb-2" aria-hidden="true" />
          <p className="text-xs text-slate-300 font-semibold">No evidence attached yet</p>
          <p className="text-[11px] text-slate-400 mt-0.5 max-w-sm mx-auto">
            Findings cannot be confirmed without at least one supporting evidence item. Upload a screenshot, raw tool output, or add an assessor note.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {evidences.map((item) => (
            <EvidenceItemView key={item.id} evidence={item} />
          ))}
        </div>
      )}

      {/* Modals */}
      <EvidenceUploadModal
        isOpen={uploadOpen}
        onClose={() => setUploadOpen(false)}
        findingId={findingId}
      />
      <EvidenceNoteModal
        isOpen={noteOpen}
        onClose={() => setNoteOpen(false)}
        findingId={findingId}
      />
    </div>
  );
}
