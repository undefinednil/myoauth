import { apiPost, type CommonResp } from "./basic.ts";

export type LoginReq = {
  username: string;
  password: string;
  clientId: string;
  codeChallenge: string;
  redirect: string;
  scope?: string;
  state: string;
  nonce?: string;
};

export type LoginResp = { authorizationCode: string } & CommonResp;

export function login(req: LoginReq) {
  return apiPost<LoginReq, LoginResp>("/auth/login", req);
}
