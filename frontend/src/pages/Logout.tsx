import { Link, useSearchParams } from "react-router-dom";
import { PageLayout, ThemeToggle } from "../components/PageLayout.tsx";

export function Logout() {
  const [searchParams] = useSearchParams();
  const state = searchParams.get("state");

  return (
    <PageLayout variant="centered">
      <div className="card card-narrow card-center">
        <span className="success-mark" aria-hidden="true">
          ✓
        </span>
        <h1 className="card-title">You have been signed out</h1>
        <p className="card-subtitle">
          Your session has ended. You can close this window or return home.
        </p>
        {state ? <p className="mono muted">state: {state}</p> : null}
        <Link className="btn btn-primary mt-2" to="/">
          Back to home
        </Link>
        <div className="card-footer-row">
          <ThemeToggle />
        </div>
      </div>
    </PageLayout>
  );
}
