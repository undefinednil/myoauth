export function Spinner({
  size = "md",
  label = "Loading",
}: {
  size?: "sm" | "md" | "lg";
  label?: string;
}) {
  return (
    <span
      className={`spinner spinner-${size}`}
      role="status"
      aria-label={label}
    />
  );
}
