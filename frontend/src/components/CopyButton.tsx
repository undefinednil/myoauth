import { useState } from "react";
import { Button } from "./Button.tsx";

async function writeClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

export function CopyButton({
  value,
  label = "Copy",
  disabled = false,
}: {
  value: string;
  label?: string;
  disabled?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function onClick() {
    try {
      await writeClipboard(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard access can be denied; nothing actionable for the user here
    }
  }

  return (
    <Button
      variant="ghost"
      onClick={onClick}
      disabled={disabled || value.length === 0}
      aria-label={`${label} to clipboard`}
    >
      {copied ? "Copied" : label}
    </Button>
  );
}
