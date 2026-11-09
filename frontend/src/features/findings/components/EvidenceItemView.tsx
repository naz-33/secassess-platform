import { useState, useEffect } from "react";
import { Download, Copy, Check, FileText, Image, ShieldAlert, Loader2 } from "lucide-react";
import { Button } from "../../../components/Button";
import { CodeBlock } from "../../../components/CodeBlock";
import { findingsApi } from "../api";
import type { EvidenceRead } from "../../../api/types";

interface EvidenceItemViewProps {
  evidence: EvidenceRead;
}

export function EvidenceItemView({ evidence }: EvidenceItemViewProps) {
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [imgError, setImgError] = useState(false);
  const [imgLoading, setImgLoading] = useState(false);
  const [showFullOutput, setShowFullOutput] = useState(false);

  const filename = evidence.original_filename || "";
  const isImage =
    evidence.type === "screenshot" ||
    filename.endsWith(".png") ||
    filename.endsWith(".jpg") ||
    filename.endsWith(".jpeg") ||
    filename.endsWith(".webp");

  // Safe authenticated image preview: fetch via authenticated client -> Blob -> object URL
  useEffect(() => {
    let active = true;
    let url: string | null = null;

    if (isImage && !evidence.content) {
      setImgLoading(true);
      findingsApi
        .downloadEvidence(evidence.id)
        .then(({ blob }) => {
          if (!active) return;
          // Validate MIME strictly: only image/png, image/jpeg, image/webp allowed
          if (!["image/png", "image/jpeg", "image/webp"].includes(blob.type)) {
            setImgError(true);
            return;
          }
          url = URL.createObjectURL(blob);
          setObjectUrl(url);
        })
        .catch(() => {
          if (active) setImgError(true);
        })
        .finally(() => {
          if (active) setImgLoading(false);
        });
    }

    return () => {
      active = false;
      if (url) {
        URL.revokeObjectURL(url);
      }
    };
  }, [evidence.id, isImage, evidence.content]);

  const handleCopySha = () => {
    if (evidence.sha256) {
      navigator.clipboard.writeText(evidence.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = async () => {
    try {
      setDownloading(true);
      const { blob, filename: headerFilename } = await findingsApi.downloadEvidence(evidence.id);
      const safeFilename =
        headerFilename ||
        evidence.original_filename ||
        `evidence-${evidence.id.slice(0, 8)}.${isImage ? "png" : "txt"}`;

      // Create download trigger
      const tempUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = tempUrl;
      a.download = safeFilename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(tempUrl);
    } catch {
      // Handled gracefully
    } finally {
      setDownloading(false);
    }
  };

  const textContent = evidence.content || "";
  const isLongText = textContent.length > 800;
  const displayedText = showFullOutput || !isLongText ? textContent : textContent.slice(0, 800) + "\n\n... [Output truncated. Click 'Show full output' below]";

  return (
    <div
      id={`evidence-${evidence.id}`}
      className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3"
    >
      {/* Evidence Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
        <div className="flex items-center gap-2">
          {isImage ? (
            <Image className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          ) : (
            <FileText className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          )}
          <span className="font-semibold text-xs text-slate-100">
            {evidence.label || "Evidence Item"}
          </span>
          <span className="text-[10px] font-mono uppercase bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded">
            {evidence.type}
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">
            {new Date(evidence.captured_at).toLocaleString()}
          </span>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDownload}
            disabled={downloading}
            isLoading={downloading}
            className="h-7 text-xs gap-1 text-slate-300 hover:text-white"
          >
            <Download className="h-3 w-3" />
            <span>Download</span>
          </Button>
        </div>
      </div>

      {/* Metadata strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-[11px] text-slate-400 bg-slate-900/40 p-2 rounded">
        <div>
          <span className="text-slate-500">Original File: </span>
          <span className="font-mono text-slate-300">{evidence.original_filename || "—"}</span>
        </div>
        <div>
          <span className="text-slate-500">Uploaded By: </span>
          <span className="font-mono text-slate-300">
            {evidence.uploaded_by ? evidence.uploaded_by.slice(0, 8) : "System"}
          </span>
        </div>
        {evidence.sha256 && (
          <div className="sm:col-span-2 md:col-span-3 flex items-center gap-2">
            <span className="text-slate-500">SHA-256: </span>
            <span className="font-mono text-slate-300 text-[10px] truncate max-w-sm">
              {evidence.sha256}
            </span>
            <button
              type="button"
              onClick={handleCopySha}
              className="text-slate-400 hover:text-slate-200 p-0.5"
              title="Copy SHA-256"
            >
              {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}
      </div>

      {/* Render text note or output safely in CodeBlock as plain text */}
      {textContent && (
        <div className="space-y-1.5">
          <CodeBlock content={displayedText} />
          {isLongText && (
            <div className="flex items-center justify-between text-xs pt-1">
              <button
                type="button"
                onClick={() => setShowFullOutput(!showFullOutput)}
                className="text-cyan-400 hover:text-cyan-300 hover:underline font-medium"
              >
                {showFullOutput ? "Collapse output" : "Show full output"}
              </button>
              <Button size="sm" variant="ghost" onClick={handleDownload} className="h-6 text-xs text-slate-400">
                Download as text
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Authenticated Image Preview */}
      {isImage && (
        <div className="mt-2">
          {imgLoading && (
            <div className="h-48 flex items-center justify-center bg-slate-900 rounded border border-slate-800 text-slate-400 text-xs gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
              <span>Loading preview securely...</span>
            </div>
          )}
          {imgError && (
            <div className="p-4 bg-slate-900 rounded border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
              <span>Preview unavailable or format not supported for preview. Use the Download button above.</span>
            </div>
          )}
          {objectUrl && !imgError && (
            <div className="rounded border border-slate-800 overflow-hidden bg-slate-900/50 p-1 flex justify-center">
              <img
                src={objectUrl}
                alt={evidence.label || "Evidence preview"}
                className="max-h-96 max-w-full rounded object-contain"
                onError={() => setImgError(true)}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
