import {
  type Dispatch,
  type SetStateAction,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  type Client,
  type ClientCreateReq,
  type ClientDeleteReq,
  adminLoginApi,
  adminLogoutApi,
  clientCreateApi,
  clientDeleteApi,
  clientListApi,
} from "./apis/setup.ts";
import { Button } from "./components/Button.tsx";
import { Input } from "./components/Input.tsx";

export function Admin() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [warn, setWarn] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);
  const [clients, setClients] = useState<Client[]>([]);
  const [triggerRefresh, setTriggerRefresh] = useState(0);
  const adminPasswordRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (triggerRefresh < 0) {
      return;
    }
    if (loggedIn) {
      clientListApi(setWarn).then((resp) => {
        if (resp) {
          setClients(resp.clients);
        } else {
          setLoggedIn(false);
        }
      });
    }
  }, [loggedIn, triggerRefresh]);

  function login() {
    if (!adminPasswordRef.current?.value) {
      setWarn("Password is required");
      return;
    }
    adminLoginApi(adminPasswordRef.current.value, setWarn).then((resp) => {
      if (resp) {
        setLoggedIn(true);
        setWarn("");
      }
    });
  }

  function logout() {
    adminLogoutApi(setWarn).then(() => {
      setLoggedIn(false);
      setClients([]);
    });
  }

  function clientDelete(id: number) {
    const req: ClientDeleteReq = { id };
    clientDeleteApi(req, setWarn).then((resp) => {
      if (resp !== null) {
        setTriggerRefresh((prev) => prev + 1);
      }
    });
  }

  return (
    <div className={"card"}>
      <h1>Admin Page</h1>
      {warn && <span className={"warn"}>{warn}</span>}
      {!loggedIn && (
        <div>
          <Input
            label={"Admin Password"}
            inputType={"password"}
            myRef={adminPasswordRef}
            enter={login}
            buttonText={"Login"}
          />
        </div>
      )}
      {loggedIn && (
        <div className={"flex-basic-column"}>
          <div className={"flex-basic"}>
            <h2>Client list</h2>
            <Button text={"Logout"} click={logout} />
          </div>
          {!showAddForm && (
            <Button
              text={"Add"}
              click={() => {
                setShowAddForm(true);
              }}
            />
          )}
          {showAddForm && (
            <AddForm
              setShowAddForm={setShowAddForm}
              setWarn={setWarn}
              setTriggerRefresh={setTriggerRefresh}
            />
          )}
          <table>
            <thead>
              <tr>
                <th>Client Id</th>
                <th>Access Token Age</th>
                <th>Refresh Token Age</th>
                <th>Redirects</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => {
                return (
                  <tr key={client.id ?? 0}>
                    <td>{client.clientId}</td>
                    <td>{client.accessTokenAge}</td>
                    <td>{client.refreshTokenAge}</td>
                    <td>{client.redirects}</td>
                    <td>
                      <Button
                        text={"Delete"}
                        click={() => {
                          clientDelete(client.id ?? 0);
                        }}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AddForm({
  setShowAddForm,
  setWarn,
  setTriggerRefresh,
}: {
  setShowAddForm: Dispatch<SetStateAction<boolean>>;
  setWarn: Dispatch<SetStateAction<string>>;
  setTriggerRefresh: Dispatch<SetStateAction<number>>;
}) {
  const clientIdRef = useRef<HTMLInputElement | null>(null);
  const secretRef = useRef<HTMLInputElement | null>(null);
  const accessAgeRef = useRef<HTMLInputElement | null>(null);
  const refreshAgeRef = useRef<HTMLInputElement | null>(null);
  const redirectRef = useRef<HTMLInputElement | null>(null);

  function click() {
    if (
      clientIdRef.current &&
      secretRef.current &&
      accessAgeRef.current &&
      refreshAgeRef.current &&
      redirectRef.current
    ) {
      if (
        clientIdRef.current.value &&
        secretRef.current.value &&
        accessAgeRef.current.value &&
        refreshAgeRef.current.value &&
        redirectRef.current.value
      ) {
        const client: ClientCreateReq = {
          clientId: clientIdRef.current.value,
          secret: secretRef.current.value,
          accessTokenAge: +accessAgeRef.current.value,
          refreshTokenAge: +refreshAgeRef.current.value,
          redirects: redirectRef.current.value,
        };
        clientCreateApi(client, setWarn).then((resp) => {
          if (resp) {
            setShowAddForm(false);
            setTriggerRefresh((prev) => prev + 1);
          }
        });
      }
    }
  }

  return (
    <div className={"flex-basic-column"}>
      <Input label={"Client Id"} inputType={"text"} myRef={clientIdRef} />
      <Input label={"Secret"} inputType={"password"} myRef={secretRef} />
      <Input
        label={"Access Token Age (hours)"}
        inputType={"text"}
        myRef={accessAgeRef}
      />
      <Input
        label={"Refresh Token Age (hours)"}
        inputType={"text"}
        myRef={refreshAgeRef}
      />
      <Input
        label={"Redirects (separate by comma)"}
        inputType={"text"}
        myRef={redirectRef}
      />
      <Button text={"Add"} click={click} />
    </div>
  );
}
