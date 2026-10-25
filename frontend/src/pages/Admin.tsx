import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  ApiError,
  errorMessage,
  setUnauthorizedHandler,
} from "../apis/basic.ts";
import {
  type Client,
  adminLogin,
  adminLogout,
  clientCreate,
  clientDelete,
  clientList,
  clientUpdate,
  sessionRevoke,
} from "../apis/setup.ts";
import { Badge } from "../components/Badge.tsx";
import { Button } from "../components/Button.tsx";
import { ConfirmDialog } from "../components/ConfirmDialog.tsx";
import { CopyButton } from "../components/CopyButton.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { Modal } from "../components/Modal.tsx";
import { NumberField } from "../components/NumberField.tsx";
import {
  PageHeader,
  PageLayout,
  ThemeToggle,
} from "../components/PageLayout.tsx";
import { Spinner } from "../components/Spinner.tsx";
import { type Column, Table } from "../components/Table.tsx";
import { TextField } from "../components/TextField.tsx";
import { useToast } from "../components/Toast.tsx";

type AuthState = "loading" | "unauth" | "auth";
type EditorState = { mode: "create" } | { mode: "edit"; client: Client } | null;

export function Admin() {
  const toast = useToast();
  const [auth, setAuth] = useState<AuthState>("loading");
  const authRef = useRef<AuthState>("loading");
  authRef.current = auth;
  const [clients, setClients] = useState<Client[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [editor, setEditor] = useState<EditorState>(null);
  const [deleteTarget, setDeleteTarget] = useState<Client | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<{
    clientId: number;
    label: string;
  } | null>(null);
  const [revoking, setRevoking] = useState(false);

  const loadClients = useCallback(async () => {
    setRefreshing(true);
    try {
      const resp = await clientList();
      setClients(resp.clients);
      setAuth("auth");
    } catch (err) {
      if (err instanceof ApiError && err.unauthorized) {
        setAuth("unauth");
      } else {
        toast.error(errorMessage(err));
        setAuth((prev) => (prev === "loading" ? "unauth" : prev));
      }
    } finally {
      setRefreshing(false);
    }
  }, [toast]);

  useEffect(() => {
    void loadClients();
  }, [loadClients]);

  useEffect(() => {
    return setUnauthorizedHandler(() => {
      if (authRef.current === "auth") {
        setEditor(null);
        setDeleteTarget(null);
        toast.error("Your admin session expired. Please sign in again.");
      }
      setAuth("unauth");
    });
  }, [toast]);

  async function logout() {
    try {
      await adminLogout();
    } catch {
      // logging out locally is enough even if the request fails
    }
    setClients([]);
    setAuth("unauth");
    toast.info("Signed out");
  }

  async function confirmRevoke() {
    if (!revokeTarget) {
      return;
    }
    setRevoking(true);
    try {
      await sessionRevoke(revokeTarget.clientId);
      toast.success(
        revokeTarget.clientId === 0
          ? "Revoked all sessions"
          : `Revoked sessions for "${revokeTarget.label}"`,
      );
      setRevokeTarget(null);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRevoking(false);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) {
      return;
    }
    setDeleting(true);
    try {
      await clientDelete(deleteTarget.id);
      toast.success(`Deleted client "${deleteTarget.clientId}"`);
      setDeleteTarget(null);
      await loadClients();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setDeleting(false);
    }
  }

  if (auth === "loading") {
    return (
      <PageLayout variant="centered">
        <div className="card card-narrow card-center">
          <Spinner size="lg" label="Loading admin console" />
        </div>
      </PageLayout>
    );
  }

  if (auth === "unauth") {
    return (
      <PageLayout variant="centered">
        <AdminLoginCard onSuccess={loadClients} />
      </PageLayout>
    );
  }

  const columns: Column<Client>[] = [
    {
      key: "clientId",
      header: "Client ID",
      render: (client) => <span className="mono">{client.clientId}</span>,
    },
    {
      key: "redirects",
      header: "Redirect URIs",
      render: (client) => <RedirectChips redirects={client.redirects} />,
    },
    {
      key: "access",
      header: "Access token",
      render: (client) => `${client.accessTokenAge} h`,
    },
    {
      key: "refresh",
      header: "Refresh token",
      render: (client) => `${client.refreshTokenAge} h`,
    },
    {
      key: "actions",
      header: "Actions",
      className: "cell-actions",
      render: (client) => (
        <div className="row-actions">
          <Button
            variant="secondary"
            onClick={() => setEditor({ mode: "edit", client })}
          >
            Edit
          </Button>
          <Button
            variant="secondary"
            onClick={() =>
              setRevokeTarget({ clientId: client.id, label: client.clientId })
            }
          >
            Revoke sessions
          </Button>
          <Button variant="danger" onClick={() => setDeleteTarget(client)}>
            Delete
          </Button>
        </div>
      ),
    },
  ];

  return (
    <PageLayout>
      <PageHeader
        title="Admin console"
        subtitle="Manage OAuth2 clients registered with this provider."
        actions={
          <>
            <ThemeToggle />
            <Button variant="secondary" onClick={logout}>
              Sign out
            </Button>
          </>
        }
      />

      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Clients</h2>
          <div className="panel-header-actions">
            {refreshing ? (
              <Spinner size="sm" label="Refreshing clients" />
            ) : null}
            <Button
              variant="secondary"
              onClick={() =>
                setRevokeTarget({ clientId: 0, label: "all clients" })
              }
            >
              Revoke all sessions
            </Button>
            <Button onClick={() => setEditor({ mode: "create" })}>
              Add client
            </Button>
          </div>
        </div>

        {clients.length === 0 ? (
          <EmptyState
            title="No clients yet"
            description="Register your first OAuth2 client to get started."
            action={
              <Button onClick={() => setEditor({ mode: "create" })}>
                Add client
              </Button>
            }
          />
        ) : (
          <Table
            columns={columns}
            rows={clients}
            getRowKey={(client) => client.id}
            caption="Registered OAuth2 clients"
          />
        )}
      </section>

      <ClientFormModal
        editor={editor}
        onClose={() => setEditor(null)}
        onSaved={loadClients}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete client"
        message={
          <>
            Permanently delete <strong>{deleteTarget?.clientId}</strong>?
            Clients using it will no longer be able to authenticate.
          </>
        }
        confirmLabel="Delete"
        danger
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />

      <ConfirmDialog
        open={revokeTarget !== null}
        title="Revoke sessions"
        message={
          <>
            Revoke all active refresh token sessions for{" "}
            <strong>{revokeTarget?.label}</strong>? Signed-in users will need to
            authenticate again.
          </>
        }
        confirmLabel="Revoke"
        danger
        loading={revoking}
        onConfirm={confirmRevoke}
        onCancel={() => setRevokeTarget(null)}
      />
    </PageLayout>
  );
}

function RedirectChips({ redirects }: { redirects: string }) {
  const uris = redirects
    .split(",")
    .map((uri) => uri.trim())
    .filter(Boolean);
  if (uris.length === 0) {
    return <span className="muted">None</span>;
  }
  return (
    <div className="chips">
      {uris.map((uri) => (
        <Badge key={uri} variant="info">
          {uri}
        </Badge>
      ))}
    </div>
  );
}

function AdminLoginCard({ onSuccess }: { onSuccess: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!password) {
      setError("Password is required");
      return;
    }
    setError("");
    setLoading(true);
    try {
      await adminLogin(password);
      setPassword("");
      toast.success("Signed in");
      onSuccess();
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="card card-narrow" onSubmit={onSubmit} noValidate>
      <div className="card-heading">
        <span className="brand-mark" aria-hidden="true">
          M
        </span>
        <h1 className="card-title">Admin sign in</h1>
        <p className="card-subtitle">
          Enter the admin password configured on the server.
        </p>
      </div>
      <TextField
        label="Admin password"
        type="password"
        reveal
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        error={error}
        autoComplete="current-password"
        autoFocus
      />
      <Button type="submit" loading={loading} block className="mt-2">
        Sign in
      </Button>
      <div className="card-footer-row">
        <ThemeToggle />
      </div>
    </form>
  );
}

function ClientFormModal({
  editor,
  onClose,
  onSaved,
}: {
  editor: EditorState;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const open = editor !== null;
  const mode = editor?.mode ?? "create";
  const client = editor?.mode === "edit" ? editor.client : null;

  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [redirects, setRedirects] = useState("");
  const [accessTokenAge, setAccessTokenAge] = useState("1");
  const [refreshTokenAge, setRefreshTokenAge] = useState("720");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!editor) {
      return;
    }
    if (editor.mode === "edit") {
      setClientId(editor.client.clientId);
      setRedirects(editor.client.redirects);
      setAccessTokenAge(String(editor.client.accessTokenAge));
      setRefreshTokenAge(String(editor.client.refreshTokenAge));
      setSecret("");
    } else {
      setClientId("");
      setRedirects("");
      setAccessTokenAge("1");
      setRefreshTokenAge("720");
      setSecret("");
    }
    setErrors({});
  }, [editor]);

  function generateSecret() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    setSecret(
      Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
  }

  function validate(): Record<string, string> {
    const found: Record<string, string> = {};
    const trimmedClientId = clientId.trim();
    const trimmedRedirects = redirects.trim();
    const access = Number(accessTokenAge);
    const refresh = Number(refreshTokenAge);

    if (!trimmedClientId) {
      found.clientId = "Client ID is required";
    } else if (trimmedClientId.length > 256) {
      found.clientId = "Client ID must be 256 characters or fewer";
    }
    if (mode === "create" && !secret) {
      found.secret = "Secret is required";
    } else if (secret.length > 256) {
      found.secret = "Secret must be 256 characters or fewer";
    }
    if (!trimmedRedirects) {
      found.redirects = "At least one redirect URI is required";
    } else if (trimmedRedirects.length > 2048) {
      found.redirects = "Redirects must be 2048 characters or fewer";
    }
    if (!Number.isFinite(access) || access <= 0) {
      found.accessTokenAge = "Must be a number greater than 0";
    }
    if (!Number.isFinite(refresh) || refresh <= 0) {
      found.refreshTokenAge = "Must be a number greater than 0";
    } else if (Number.isFinite(access) && refresh <= access) {
      found.refreshTokenAge = "Must be longer than the access token age";
    }
    return found;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const found = validate();
    setErrors(found);
    if (Object.keys(found).length > 0) {
      return;
    }
    setSubmitting(true);
    try {
      const payload = {
        clientId: clientId.trim(),
        secret,
        redirects: redirects.trim(),
        accessTokenAge: Number(accessTokenAge),
        refreshTokenAge: Number(refreshTokenAge),
      };
      if (mode === "edit" && client) {
        await clientUpdate({ id: client.id, ...payload });
        toast.success("Client updated");
      } else {
        await clientCreate(payload);
        toast.success("Client created");
      }
      onSaved();
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === "edit" ? "Edit client" : "Add client"}
      description={
        mode === "edit"
          ? "Update the client configuration. Leave the secret blank to keep the current one."
          : "Register a new OAuth2 client."
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button type="submit" form="client-form" loading={submitting}>
            {mode === "edit" ? "Save changes" : "Create client"}
          </Button>
        </>
      }
    >
      <form id="client-form" className="form-grid" onSubmit={submit} noValidate>
        <TextField
          label="Client ID"
          value={clientId}
          onChange={(event) => setClientId(event.target.value)}
          error={errors.clientId}
          required
          autoComplete="off"
        />
        <div>
          <TextField
            label="Client secret"
            type="password"
            reveal
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            error={errors.secret}
            hint={
              mode === "edit"
                ? "Leave blank to keep the current secret"
                : "Shared secret used by the client"
            }
            autoComplete="new-password"
          />
          <div className="inline-actions">
            <Button variant="secondary" onClick={generateSecret}>
              Generate secret
            </Button>
            <CopyButton value={secret} label="Copy secret" />
          </div>
        </div>
        <TextField
          label="Redirect URIs"
          value={redirects}
          onChange={(event) => setRedirects(event.target.value)}
          error={errors.redirects}
          hint="Comma-separated list of allowed redirect URIs"
          placeholder="https://app.example.com/callback"
          autoComplete="off"
          required
        />
        <div className="form-row">
          <NumberField
            label="Access token age (hours)"
            value={accessTokenAge}
            onChange={(event) => setAccessTokenAge(event.target.value)}
            error={errors.accessTokenAge}
            min={1}
            step={1}
            required
          />
          <NumberField
            label="Refresh token age (hours)"
            value={refreshTokenAge}
            onChange={(event) => setRefreshTokenAge(event.target.value)}
            error={errors.refreshTokenAge}
            min={1}
            step={1}
            required
          />
        </div>
      </form>
    </Modal>
  );
}
