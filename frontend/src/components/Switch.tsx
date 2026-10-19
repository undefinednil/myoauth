import { useId } from "react";

type Props = {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  hint?: string;
  id?: string;
  disabled?: boolean;
};

export function Switch({
  label,
  checked,
  onChange,
  hint,
  id,
  disabled = false,
}: Props) {
  const generatedId = useId();
  const fieldId = id ?? generatedId;

  return (
    <div className="switch-field">
      <button
        type="button"
        id={fieldId}
        role="switch"
        aria-checked={checked}
        aria-describedby={hint ? `${fieldId}-hint` : undefined}
        className={`switch${checked ? " switch-on" : ""}`}
        onClick={() => onChange(!checked)}
        disabled={disabled}
      >
        <span className="switch-track">
          <span className="switch-thumb" />
        </span>
        <span className="switch-label">{label}</span>
      </button>
      {hint ? (
        <p id={`${fieldId}-hint`} className="field-hint">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
