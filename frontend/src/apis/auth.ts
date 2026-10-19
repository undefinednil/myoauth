import type { Dispatch, SetStateAction } from "react";
import { type CommonResp, axiosPost } from "./basic.ts";

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

export async function loginApi(
  req: LoginReq,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  return axiosPost<LoginReq, LoginResp>("/auth/login", req, setWarn);
}
