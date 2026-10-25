import { type FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { type LoginReq, login } from "../apis/auth.ts";
import { errorMessage } from "../apis/basic.ts";
import { Badge } from "../components/Badge.tsx";
import { Button } from "../components/Button.tsx";
import { PageLayout, ThemeToggle } from "../components/PageLayout.tsx";
import { Switch } from "../components/Switch.tsx";
import { TextField } from "../components/TextField.tsx";

const USERNAME_KEY = "myoauth-username";

function readRememberedUsername(): string {
  try {
    return window.localStorage.getItem(USERNAME_KEY) ?? "";
  } catch {
    return "";
  }
}

export function Login() {
  const [searchParams] = useSearchParams();
  const clientId = searchParams.get("client_id") ?? "";
  const codeChallenge = searchParams.get("code_challenge") ?? "";
  const redirect = searchParams.get("redirect_uri") ?? "";
  const scope = (searchParams.get("scope") ?? "").trim();
  const state = searchParams.get("state") ?? "";
  const nonce = searchParams.get("nonce") ?? "";

  const remembered = readRememberedUsername();
  const [username, setUsername] = useState(remembered);
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(remembered !== "");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const redirectValid = (() => {
    if (!redirect) {
      return false;
    }
    try {
      new URL(redirect);
      return true;
    } catch {
      return false;
    }
  })();

  const missingParams =
    !clientId || !codeChallenge || !redirect || !state || !redirectValid;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (missingParams) {
      return;
    }
    if (!username.trim() || !password) {
      setError("Username and password are required");
      return;
    }
    setError("");
    setLoading(true);
    try {
      try {
        if (remember) {
          window.localStorage.setItem(USERNAME_KEY, username);
        } else {
          window.localStorage.removeItem(USERNAME_KEY);
        }
      } catch {
        // ignore storage failures
      }
      const req: LoginReq = {
        username: username.trim(),
        password,
        clientId,
        codeChallenge,
        redirect,
        scope,
        state,
        nonce,
      };
      const resp = await login(req);
      const callbackUrl = new URL(redirect);
      callbackUrl.searchParams.set("code", resp.authorizationCode);
      callbackUrl.searchParams.set("state", state);
      window.location.replace(callbackUrl.toString());
    } catch (err) {
      setError(errorMessage(err));
      setLoading(false);
    }
  }

  const scopes = scope.split(" ").filter(Boolean);

  return (
    <PageLayout variant="centered">
      <form className="card card-narrow" onSubmit={onSubmit} noValidate>
        <div className="card-heading">
          <span className="brand-mark" aria-hidden="true">
            M
          </span>
          <h1 className="card-title">Sign in</h1>
          <p className="card-subtitle">
            {missingParams
              ? "This sign-in page is opened by an application."
              : "Continue to authorize the requested application."}
          </p>
        </div>

        {missingParams ? (
          <div className="alert alert-error" role="alert">
            <strong>Invalid sign-in link.</strong>
            <p>
              Required parameters are missing. Open this page through the
              application that requested access, or return{" "}
              <Link to="/">home</Link>.
            </p>
          </div>
        ) : (
          <>
            <dl className="request-summary">
              <div>
                <dt>Application</dt>
                <dd className="mono">{clientId}</dd>
              </div>
              {scopes.length > 0 ? (
                <div>
                  <dt>Requested scopes</dt>
                  <dd className="chips">
                    {scopes.map((item) => (
                      <Badge key={item} variant="neutral">
                        {item}
                      </Badge>
                    ))}
                  </dd>
                </div>
              ) : null}
            </dl>

            <TextField
              label="Username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoFocus
              required
            />
            <TextField
              label="Password"
              type="password"
              reveal
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              error={error}
              autoComplete="current-password"
              required
            />
            <Switch
              label="Remember username"
              checked={remember}
              onChange={setRemember}
            />
            <Button type="submit" loading={loading} block className="mt-2">
              Sign in
            </Button>
          </>
        )}

        <div className="card-footer-row">
          <ThemeToggle />
        </div>
      </form>
    </PageLayout>
  );
}
