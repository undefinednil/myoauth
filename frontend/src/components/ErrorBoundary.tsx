import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled UI error", error, info);
  }

  render() {
    const { error } = this.state;
    if (error) {
      return (
        <div className="error-boundary">
          <div className="card card-narrow">
            <h1 className="card-title">Something went wrong</h1>
            <p className="muted">
              An unexpected error occurred while rendering this page.
            </p>
            <pre className="error-boundary-detail">{error.message}</pre>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => window.location.reload()}
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
