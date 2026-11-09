import { useState } from "react";
import { Copy, Check, Download } from "lucide-react";
import { Button } from "./Button";

export interface CodeBlockProps {
  content?: string | null;
  maxDisplayLength?: number;
  filename?: string;
  className?: string;
}

/**
 * Secure CodeBlock component for untrusted scanner output and raw text.
 * Strictly renders via standard text nodes (NO dangerouslySetInnerHTML).
 */
export function CodeBlock({
  content,
  maxDisplayLength = 10000,
  filename = "scan-output.txt",
  className = "",
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const text = content ?? "";
  const isTruncated = text.length > maxDisplayLength && !expanded;
  const displayedText = isTruncated ? `${text.slice(0, maxDisplayLength)}\n\n[... Truncated for display. Click 'Show Full Output' or download file ...]` : text;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Ignore clipboard write failures in test/unsupported environments
    }
  };

  const handleDownload = () => {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (!text) {
    return (
      <div className="rounded-md border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-500">
        (No raw output captured)
      </div>
    );
  }

  return (
    <div className={`relative rounded-md border border-slate-800 bg-slate-950 shadow-inner ${className}`}>
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2 bg-slate-900/60 text-xs text-slate-400">
        <span className="font-mono">{text.length.toLocaleString()} characters (stored raw & unchanged)</span>
        <div className="flex items-center space-x-2">
          {text.length > maxDisplayLength && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setExpanded(!expanded)}
              className="text-xs py-1 px-2 text-cyan-400 hover:text-cyan-300"
            >
              {expanded ? "Collapse" : "Show Full Output"}
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            onClick={handleCopy}
            className="text-xs py-1 px-2"
            title="Copy raw text to clipboard"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400 mr-1" /> : <Copy className="h-3.5 w-3.5 mr-1" />}
            {copied ? "Copied" : "Copy"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDownload}
            className="text-xs py-1 px-2"
            title="Download raw output text file"
          >
            <Download className="h-3.5 w-3.5 mr-1" />
            Download
          </Button>
        </div>
      </div>
      <div className="max-h-[500px] overflow-auto p-4">
        {/* Strictly plain text rendering - untrusted scanner content is never parsed as HTML */}
        <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap break-all select-text font-normal leading-relaxed">
          {displayedText}
        </pre>
      </div>
    </div>
  );
}

