import type { Dispatch, SetStateAction } from "react";
import { type CommonResp, axiosDelete, axiosGet, axiosPost } from "./basic.ts";

export type Client = {
  id?: number;
  clientId: string;
  secret: string;
  redirects: string;
  accessTokenAge: number;
  refreshTokenAge: number;
};

export type ClientListResp = { clients: Client[] } & CommonResp;

export async function adminLoginApi(
  adminPassword: string,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosPost<{ adminPassword: string }, CommonResp>(
    "/setup/admin-login",
    { adminPassword },
    setWarn,
  );
}

export async function adminLogoutApi(
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosPost<object, CommonResp>("/setup/admin-logout", {}, setWarn);
}

export async function clientListApi(setWarn: Dispatch<SetStateAction<string>>) {
  return axiosGet<ClientListResp>("/setup/client-list", setWarn);
}

export type ClientCreateReq = {
  clientId: string;
  secret: string;
  redirects: string;
  accessTokenAge: number;
  refreshTokenAge: number;
};

export async function clientCreateApi(
  req: ClientCreateReq,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosPost<ClientCreateReq, CommonResp>(
    "/setup/client-create",
    req,
    setWarn,
  );
}

export type ClientDeleteReq = {
  id: number;
};

export async function clientDeleteApi(
  req: ClientDeleteReq,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosDelete<ClientDeleteReq, CommonResp>(
    "/setup/client-delete",
    req,
    setWarn,
  );
}

export type RegisterReq = {
  username: string;
  password: string;
  invitationCode: string;
};

export async function registerApi(
  req: RegisterReq,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosPost<RegisterReq, CommonResp>("/setup/register", req, setWarn);
}
