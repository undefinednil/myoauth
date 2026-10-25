import { type FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { errorMessage } from "../apis/basic.ts";
import { type RegisterReq, register } from "../apis/setup.ts";
import { Button } from "../components/Button.tsx";
import { PageLayout, ThemeToggle } from "../components/PageLayout.tsx";
import { TextField } from "../components/TextField.tsx";

const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];
const MIN_PASSWORD_LENGTH = 8;

function passwordStrength(password: string): number {
  if (!password) {
    return 0;
  }
  let score = 0;
  if (password.length >= MIN_PASSWORD_LENGTH) {
    score++;
  }
  if (password.length >= 12) {
    score++;
  }
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) {
    score++;
  }
  if (/\d/.test(password)) {
    score++;
  }
  if (/[^A-Za-z0-9]/.test(password)) {
    score++;
  }
  return Math.min(score, 4);
}

export function Register() {
  const [searchParams] = useSearchParams();
  const [invitationCode, setInvitationCode] = useState(
    searchParams.get("invitationCode") ?? "",
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  const strength = passwordStrength(password);

  function validate(): Record<string, string> {
    const found: Record<string, string> = {};
    if (!invitationCode.trim()) {
      found.invitationCode = "Invitation code is required";
    }
    if (!username.trim()) {
      found.username = "Username is required";
    } else if (username.length > 256) {
      found.username = "Username must be 256 characters or fewer";
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      found.password = `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
    } else if (password.length > 72) {
      found.password = "Password must be 72 characters or fewer";
    }
    if (confirmPassword !== password) {
      found.confirmPassword = "Passwords do not match";
    }
    return found;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const found = validate();
    setErrors(found);
    if (Object.keys(found).length > 0) {
      return;
    }
    setLoading(true);
    try {
      const req: RegisterReq = {
        username: username.trim(),
        password,
        invitationCode: invitationCode.trim(),
      };
      await register(req);
      setDone(true);
    } catch (err) {
      setErrors({ form: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  if (done) {
    return (
      <PageLayout variant="centered">
        <div className="card card-narrow card-center">
          <span className="success-mark" aria-hidden="true">
            ✓
          </span>
          <h1 className="card-title">Account created</h1>
          <p className="card-subtitle">
            You can now sign in and close this window.
          </p>
          <Link className="btn btn-secondary mt-2" to="/">
            Go to admin console
          </Link>
        </div>
      </PageLayout>
    );
  }

  return (
    <PageLayout variant="centered">
      <form className="card card-narrow" onSubmit={onSubmit} noValidate>
        <div className="card-heading">
          <span className="brand-mark" aria-hidden="true">
            M
          </span>
          <h1 className="card-title">Create an account</h1>
          <p className="card-subtitle">
            Register a new user account with an invitation code.
          </p>
        </div>

        {errors.form ? (
          <div className="alert alert-error" role="alert">
            {errors.form}
          </div>
        ) : null}

        <TextField
          label="Invitation code"
          value={invitationCode}
          onChange={(event) => setInvitationCode(event.target.value)}
          error={errors.invitationCode}
          autoComplete="off"
          required
        />
        <TextField
          label="Username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          error={errors.username}
          autoComplete="username"
          required
        />
        <div>
          <TextField
            label="Password"
            type="password"
            reveal
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            error={errors.password}
            autoComplete="new-password"
            required
          />
          {password ? (
            <div className="strength" aria-live="polite">
              <div className="strength-bars">
                {[0, 1, 2, 3].map((index) => (
                  <span
                    key={index}
                    className={`strength-bar${
                      index < strength ? ` strength-bar-${strength}` : ""
                    }`}
                  />
                ))}
              </div>
              <span className="strength-label">
                {STRENGTH_LABELS[strength]}
              </span>
            </div>
          ) : null}
        </div>
        <TextField
          label="Confirm password"
          type="password"
          reveal
          value={confirmPassword}
          onChange={(event) => setConfirmPassword(event.target.value)}
          error={errors.confirmPassword}
          autoComplete="new-password"
          required
        />
        <Button type="submit" loading={loading} block className="mt-2">
          Create account
        </Button>

        <div className="card-footer-row">
          <ThemeToggle />
        </div>
      </form>
    </PageLayout>
  );
}
