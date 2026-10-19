import { type InputHTMLAttributes, useId, useState } from "react";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & {
  label: string;
  hint?: string;
  error?: string;
  id?: string;
  reveal?: boolean;
};

export function TextField({
  label,
  hint,
  error,
  id,
  reveal = false,
  type = "text",
  className,
  ...rest
}: Props) {
  const generatedId = useId();
  const fieldId = id ?? generatedId;
  const [show, setShow] = useState(false);
  const isPassword = type === "password";
  const resolvedType = isPassword && reveal && show ? "text" : type;

  const describedBy =
    [hint ? `${fieldId}-hint` : null, error ? `${fieldId}-error` : null]
      .filter(Boolean)
      .join(" ") || undefined;

  return (
    <div
      className={["field", error ? "field-invalid" : "", className ?? ""]
        .filter(Boolean)
        .join(" ")}
    >
      <label className="field-label" htmlFor={fieldId}>
        {label}
        {rest.required ? (
          <span className="field-required" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      <div className="field-input-wrap">
        <input
          id={fieldId}
          className="field-input"
          type={resolvedType}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          {...rest}
        />
        {isPassword && reveal ? (
          <button
            type="button"
            className="field-reveal"
            onClick={() => setShow((value) => !value)}
            aria-label={show ? "Hide password" : "Show password"}
            aria-pressed={show}
          >
            {show ? "Hide" : "Show"}
          </button>
        ) : null}
      </div>
      {hint && !error ? (
        <p id={`${fieldId}-hint`} className="field-hint">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${fieldId}-error`} className="field-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
