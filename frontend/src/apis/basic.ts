import axios from "axios";
import type { Dispatch, SetStateAction } from "react";

const BASE = import.meta.env.DEV
  ? "/api"
  : (import.meta.env.VITE_API_BASE as string) || "";

axios.defaults.withCredentials = true;

type CanToString = {
  toString: () => string;
};

export type CommonResp = {
  ok: boolean;
  msg: string;
};
export async function axiosGet<T extends CommonResp>(
  url: string,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  try {
    const resp = await axios.get(`${BASE}${url}`);
    const data = resp.data as T;
    if (!data.ok) {
      setWarn(data.msg);
      return null;
    }
    setWarn("");
    return data;
  } catch (err) {
    warn(err as CanToString, setWarn);
    return null;
  }
}

export async function axiosPost<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  try {
    const resp = await axios.post(`${BASE}${url}`, body);
    const data = resp.data as TRes;
    if (!data.ok) {
      setWarn(data.msg);
      return null;
    }
    setWarn("");
    return data;
  } catch (err) {
    warn(err as CanToString, setWarn);
    return null;
  }
}

export async function axiosDelete<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
  setWarn: Dispatch<SetStateAction<string>>,
) {
  try {
    const resp = await axios.delete(`${BASE}${url}`, { data: body });
    const data = resp.data as TRes;
    if (!data.ok) {
      setWarn(data.msg);
      return null;
    }
    setWarn("");
    return data;
  } catch (err) {
    warn(err as CanToString, setWarn);
    return null;
  }
}

function warn(err: CanToString, setWarn: Dispatch<SetStateAction<string>>) {
  setWarn(err.toString());
}
