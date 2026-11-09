import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./Button";

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  totalItems?: number;
  pageSize?: number;
}

export function Pagination({
  currentPage,
  totalPages,
  onPageChange,
  totalItems,
  pageSize,
}: PaginationProps) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between border-t border-slate-800 px-4 py-3 sm:px-6">
      <div className="text-xs text-slate-400">
        {totalItems !== undefined && pageSize !== undefined ? (
          <>
            Showing{" "}
            <span className="font-medium text-slate-200">
              {Math.min((currentPage - 1) * pageSize + 1, totalItems)}
            </span>{" "}
            to{" "}
            <span className="font-medium text-slate-200">
              {Math.min(currentPage * pageSize, totalItems)}
            </span>{" "}
            of <span className="font-medium text-slate-200">{totalItems}</span> results
          </>
        ) : (
          <>
            Page <span className="font-medium text-slate-200">{currentPage}</span> of{" "}
            <span className="font-medium text-slate-200">{totalPages}</span>
          </>
        )}
      </div>
      <div className="flex items-center space-x-2">
        <Button
          size="sm"
          variant="outline"
          disabled={currentPage <= 1}
          onClick={() => onPageChange(currentPage - 1)}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-xs text-slate-300 font-medium px-2">
          {currentPage} / {totalPages}
        </span>
        <Button
          size="sm"
          variant="outline"
          disabled={currentPage >= totalPages}
          onClick={() => onPageChange(currentPage + 1)}
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

