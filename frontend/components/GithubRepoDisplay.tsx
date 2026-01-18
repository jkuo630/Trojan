"use client";

import * as React from "react";

export type RepoVisibility = "Public" | "Private" | "Internal";

export type GithubRepoDisplayData = {
  repoName: string; // backend text
  publicStatus: RepoVisibility; // backend value
  language: string; // backend text
};

export type GithubRepoDisplayProps = {
  data: GithubRepoDisplayData;
  selected?: boolean;
  onClick?: () => void;
  className?: string;
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

/**
 * GitHub language colors come from GitHub Linguist (languages.yml "color").
 * Keeping a small subset + fallback for now.
 */
const LANGUAGE_COLORS: Record<string, string> = {
  CSS: "#563d7c",
  JavaScript: "#f1e05a",
  TypeScript: "#3178c6",
  HTML: "#e34c26",
  Python: "#3572A5",
  Java: "#b07219",
  "C++": "#f34b7d",
  C: "#555555",
  Go: "#00ADD8",
  Ruby: "#701516",
  Rust: "#dea584",
  Shell: "#89e051",
};

function languageDotColor(language: string) {
  return LANGUAGE_COLORS[language] ?? "rgb(var(--gray-rgb)/0.55)";
}

export function GithubRepoDisplay({
  data,
  selected = false,
  onClick,
  className,
}: GithubRepoDisplayProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      className={cx(
        "w-full text-left border rounded-none transition",
        "px-6 py-6",
        "cursor-pointer",
        "focus:outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--blue-rgb)/0.50)]",
        selected
          ? "border-[rgb(var(--foreground-rgb)/0.55)] bg-[rgb(var(--foreground-rgb)/0.08)]"
          : "border-[rgb(var(--foreground-rgb)/0.30)] bg-[rgb(var(--foreground-rgb)/0.03)] hover:bg-[rgb(var(--foreground-rgb)/0.06)] hover:border-[rgb(var(--foreground-rgb)/0.45)]",
        className
      )}
    >
      {/* top row */}
      <div className="flex items-start justify-between gap-4">
        <div
          className="text-[14px] font-bold font-[var(--font-sans)] text-[var(--blue)]"
          title={data.repoName}
        >
          {data.repoName}
        </div>

        <div className="shrink-0">
          <span
            className={cx(
              "inline-flex items-center justify-center",
              "rounded-full",
              "border border-[rgb(var(--gray-rgb)/0.85)]",
              "px-4 py-1",
              "text-[14px] font-bold font-[var(--font-sans)] text-[var(--gray)]"
            )}
          >
            {data.publicStatus}
          </span>
        </div>
      </div>

      {/* language row */}
      <div className="mt-5 flex items-center gap-3">
        <span
          className="h-5 w-5 rounded-full"
          style={{ backgroundColor: languageDotColor(data.language) }}
          aria-hidden="true"
        />
        <span className="text-[14px] font-normal font-[var(--font-sans)] text-[var(--gray)]">
          {data.language}
        </span>
      </div>
    </button>
  );
}
