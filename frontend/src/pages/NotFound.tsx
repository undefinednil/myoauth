import { Link } from "react-router-dom";
import { PageLayout, ThemeToggle } from "../components/PageLayout.tsx";

export function NotFound() {
  return (
    <PageLayout variant="centered">
      <div className="card card-narrow card-center">
        <span className="notfound-code">404</span>
        <h1 className="card-title">Page not found</h1>
        <p className="card-subtitle">
          The page you are looking for does not exist or has moved.
        </p>
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
