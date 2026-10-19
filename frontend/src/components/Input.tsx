import type React from "react";
import { Button } from "./Button.tsx";

export function Input({
  label,
  inputType,
  myRef,
  enter,
  buttonText,
}: {
  label: string;
  inputType: string;
  myRef: React.MutableRefObject<HTMLInputElement | null>;
  enter?: () => void;
  buttonText?: string;
}) {
  function keyDown(evt: React.KeyboardEvent) {
    if (evt.key === "Enter") {
      if (enter) {
        enter();
      }
    }
  }

  return (
    <div className={"flex-basic-column full-width"}>
      <label htmlFor={label} className={"label"}>
        {label}
      </label>
      <div className={"flex-basic"}>
        <input
          className={"input full-width"}
          id={label}
          ref={myRef}
          type={inputType}
          onKeyDown={keyDown}
        />
        {buttonText && <Button text={buttonText} click={enter} />}
      </div>
    </div>
  );
}
