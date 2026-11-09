import React, { useState } from "react";
import { PlusCircle, AlertCircle } from "lucide-react";
import { Modal } from "../../../components/Modal";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { useAddEvidenceNote } from "../hooks";
import { useToast } from "../../../components/Toast";
import { ApiError } from "../../../api/client";

interface EvidenceNoteModalProps {
  isOpen: boolean;
  onClose: () => void;
  findingId: string;
}

export function EvidenceNoteModal({ isOpen, onClose, findingId }: EvidenceNoteModalProps) {
  const { success } = useToast();
  const noteMutation = useAddEvidenceNote(findingId);

  const [label, setLabel] = useState("Assessor Note");
  const [notes, setNotes] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!notes.trim()) {
      setErrorMsg("Note content is required.");
      return;
    }

    try {
      await noteMutation.mutateAsync({
        label: label.trim() || "Assessor Note",
        notes: notes.trim(),
      });
      success("Assessor note evidence added.");
      setNotes("");
      setLabel("Assessor Note");
      setErrorMsg(null);
      onClose();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg("Failed to add note evidence.");
      }
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Add Manual Note Evidence" maxWidth="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. Manual curl reproduction steps"
          required
        />

        <div>
          <label htmlFor="evidence-text-note" className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Note & Observation Content (Required)
          </label>
          <textarea
            id="evidence-text-note"
            rows={5}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Document reproduction observations, manual curl commands, HTTP response excerpts, or bypass behavior..."
            className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            required
          />
        </div>

        {errorMsg && (
          <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <Button type="button" variant="ghost" onClick={onClose} disabled={noteMutation.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={!notes.trim() || noteMutation.isPending}
            isLoading={noteMutation.isPending}
          >
            <PlusCircle className="h-4 w-4 mr-1.5" />
            <span>Save Note Evidence</span>
          </Button>
        </div>
      </form>
    </Modal>
  );
}
