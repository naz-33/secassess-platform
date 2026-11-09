import React, { useState } from "react";
import { Upload, AlertCircle, FileUp } from "lucide-react";
import { Modal } from "../../../components/Modal";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { useUploadEvidence } from "../hooks";
import { useToast } from "../../../components/Toast";
import { ApiError } from "../../../api/client";

interface EvidenceUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  findingId: string;
}

const ALLOWED_MIME_TYPES = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "application/pdf",
  "text/plain",
];

const MAX_BYTES = 5 * 1024 * 1024; // 5 MB default matching backend config

export function EvidenceUploadModal({ isOpen, onClose, findingId }: EvidenceUploadModalProps) {
  const { success } = useToast();
  const uploadMutation = useUploadEvidence(findingId);

  const [file, setFile] = useState<File | null>(null);
  const [label, setLabel] = useState("");
  const [notes, setNotes] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const resetForm = () => {
    setFile(null);
    setLabel("");
    setNotes("");
    setErrorMsg(null);
  };

  const validateFile = (selected: File): boolean => {
    setErrorMsg(null);
    if (!ALLOWED_MIME_TYPES.includes(selected.type) && !selected.name.endsWith(".txt")) {
      setErrorMsg("Invalid file type. Allowed formats: PNG, JPEG, WEBP, PDF, TXT.");
      return false;
    }
    if (selected.size > MAX_BYTES) {
      setErrorMsg(`File is too large (${(selected.size / (1024 * 1024)).toFixed(1)} MB). Maximum allowed size is 5 MB.`);
      return false;
    }
    return true;
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      if (validateFile(selected)) {
        setFile(selected);
        if (!label) {
          setLabel(selected.name.replace(/\.[^/.]+$/, ""));
        }
      }
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const selected = e.dataTransfer.files[0];
      if (validateFile(selected)) {
        setFile(selected);
        if (!label) {
          setLabel(selected.name.replace(/\.[^/.]+$/, ""));
        }
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setErrorMsg("Please select an evidence file to upload.");
      return;
    }
    if (!label.trim()) {
      setErrorMsg("Evidence label is required.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("label", label.trim());
    if (notes.trim()) {
      formData.append("notes", notes.trim());
    }

    try {
      await uploadMutation.mutateAsync(formData);
      success("Evidence uploaded successfully.");
      resetForm();
      onClose();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg("Evidence upload failed.");
      }
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Upload Evidence File" maxWidth="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Drag and Drop Zone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors cursor-pointer ${
            dragOver
              ? "border-cyan-400 bg-cyan-950/20"
              : file
              ? "border-emerald-600/80 bg-emerald-950/10"
              : "border-slate-800 bg-slate-950/50 hover:border-slate-700"
          }`}
          onClick={() => document.getElementById("file-upload-input")?.click()}
        >
          <input
            id="file-upload-input"
            type="file"
            className="hidden"
            accept=".png,.jpg,.jpeg,.webp,.pdf,.txt"
            onChange={handleFileChange}
          />
          <FileUp className="h-8 w-8 mx-auto text-slate-400 mb-2" />
          {file ? (
            <div>
              <p className="text-xs font-semibold text-emerald-400">{file.name}</p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {(file.size / 1024).toFixed(1)} KB • {file.type || "text/plain"}
              </p>
            </div>
          ) : (
            <div>
              <p className="text-xs font-semibold text-slate-200">
                Click or drag & drop evidence file here
              </p>
              <p className="text-[11px] text-slate-400 mt-1">
                Supported: PNG, JPEG, WEBP, PDF, TXT (Max 5 MB)
              </p>
            </div>
          )}
        </div>

        <Input
          label="Evidence Label (Required)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. SQL Injection error response screenshot"
          required
        />

        <div>
          <label htmlFor="upload-notes" className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Assessor Notes (Optional)
          </label>
          <textarea
            id="upload-notes"
            rows={2}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Context regarding testing environment or parameters tested..."
            className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        {errorMsg && (
          <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <Button type="button" variant="ghost" onClick={onClose} disabled={uploadMutation.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={!file || uploadMutation.isPending}
            isLoading={uploadMutation.isPending}
          >
            <Upload className="h-4 w-4 mr-1.5" />
            <span>Upload Evidence</span>
          </Button>
        </div>
      </form>
    </Modal>
  );
}
