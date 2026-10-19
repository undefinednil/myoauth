import NProgress from "nprogress";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { type LoginReq, loginApi } from "./apis/auth.ts";
import { Button } from "./components/Button.tsx";
import { Input } from "./components/Input.tsx";

export function Login() {
  const [warn, setWarn] = useState("");
  const usernameRef = useRef<HTMLInputElement | null>(null);
  const passwordRef = useRef<HTMLInputElement | null>(null);
  const [searchParams] = useSearchParams();

  useEffect(() => {
    function onEnter(event: KeyboardEvent) {
      if (event.key === "Enter") {
        login();
      }
    }
    window.addEventListener("keydown", onEnter);
    return () => {
      window.removeEventListener("keydown", onEnter);
    };
  }, []);

  function login() {
    NProgress.start();
    const clientId = searchParams.get("client_id");
    const codeChallenge = searchParams.get("code_challenge");
    const redirect = searchParams.get("redirect_uri");
    const scope = searchParams.get("scope") ?? "";
    const state = searchParams.get("state") ?? "";
    const nonce = searchParams.get("nonce") ?? "";
    if (
      !(
        clientId &&
        codeChallenge &&
        redirect &&
        state &&
        usernameRef.current &&
        usernameRef.current.value &&
        passwordRef.current &&
        passwordRef.current.value
      )
    ) {
      setWarn("Some information is missing");
      return;
    }
    const req: LoginReq = {
      username: usernameRef.current.value,
      password: passwordRef.current.value,
      clientId: clientId,
      codeChallenge: codeChallenge,
      redirect: redirect,
      scope: scope,
      state: state,
      nonce: nonce,
    };
    loginApi(req, setWarn).then((resp) => {
      NProgress.done();
      if (resp) {
        const callbackUrl = new URL(redirect);
        callbackUrl.searchParams.set("code", resp.authorizationCode);
        callbackUrl.searchParams.set("state", state);
        window.location.replace(callbackUrl.toString());
      }
    });
  }

  return (
    <div id={"card"} className={"card"}>
      <h1>Login with MyOAuth</h1>
      {warn && <span className={"warn"}>{warn}</span>}
      <Input
        label={"Username"}
        inputType={"text"}
        myRef={usernameRef}
        enter={login}
      />
      <Input
        label={"Password"}
        inputType={"password"}
        myRef={passwordRef}
        enter={login}
      />
      <Button text={"Go"} click={login} className={"full-width mt-1"} />
    </div>
  );
}
