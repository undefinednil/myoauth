import { useState } from "react";

export function Button({
  text,
  click,
  className,
}: {
  text: string;
  click?: () => void;
  className?: string;
}) {
  const [myClassName, setMyClassName] = useState(`${className} button`);

  function mouseDown() {
    setMyClassName(`${className} button button-pressed`);
  }

  function mouseUp() {
    setMyClassName(`${className} button`);
    if (click) {
      click();
    }
  }

  function mouseLeave() {
    setMyClassName(`${className} button`);
  }

  return (
    <button
      type="button"
      className={myClassName}
      onMouseDown={mouseDown}
      onMouseUp={mouseUp}
      onMouseLeave={mouseLeave}
    >
      {text}
    </button>
  );
}
