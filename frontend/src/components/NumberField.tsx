import type { InputHTMLAttributes } from "react";
import { TextField } from "./TextField.tsx";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "type"> & {
  label: string;
  hint?: string;
  error?: string;
  id?: string;
};

export function NumberField(props: Props) {
  return <TextField type="number" inputMode="numeric" {...props} />;
}
