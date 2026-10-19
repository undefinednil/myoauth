import { apiDelete, apiGet, apiPost, type CommonResp } from "./basic.ts";

export type Client = {
  id: number;
  clientId: string;
  redirects: string;
  accessTokenAge: number;
  refreshTokenAge: number;
};

export type ClientListResp = { clients: Client[] } & CommonResp;

export type AdminLoginResp = CommonResp & { csrfToken?: string };

export function adminLogin(adminPassword: string) {
  return apiPost<{ adminPassword: string }, AdminLoginResp>(
    "/setup/admin-login",
    {
      adminPassword,
    },
  );
}

export function adminLogout() {
  return apiPost<object, CommonResp>("/setup/admin-logout", {});
}

export function clientList() {
  return apiGet<ClientListResp>("/setup/client-list");
}

export type ClientCreateReq = {
  clientId: string;
  secret: string;
  redirects: string;
  accessTokenAge: number;
  refreshTokenAge: number;
};

export function clientCreate(req: ClientCreateReq) {
  return apiPost<ClientCreateReq, CommonResp>("/setup/client-create", req);
}

export type ClientUpdateReq = {
  id: number;
  clientId: string;
  secret: string;
  redirects: string;
  accessTokenAge: number;
  refreshTokenAge: number;
};

export function clientUpdate(req: ClientUpdateReq) {
  return apiPost<ClientUpdateReq, CommonResp>("/setup/client-update", req);
}

export function clientDelete(id: number) {
  return apiDelete<{ id: number }, CommonResp>("/setup/client-delete", { id });
}

export function sessionRevoke(clientId: number) {
  return apiPost<{ clientId: number }, CommonResp>("/setup/session-revoke", {
    clientId,
  });
}

export type RegisterReq = {
  username: string;
  password: string;
  invitationCode: string;
};

export function register(req: RegisterReq) {
  return apiPost<RegisterReq, CommonResp>("/setup/register", req);
}
