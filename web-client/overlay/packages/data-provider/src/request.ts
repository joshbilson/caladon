/* eslint-disable @typescript-eslint/no-explicit-any */
import axios, { AxiosRequestConfig } from 'axios';
import type * as t from './types';

async function _get<T>(url: string, options?: AxiosRequestConfig): Promise<T> {
  const response = await axios.get(url, { ...options });
  return response.data;
}

async function _getResponse<T>(url: string, options?: AxiosRequestConfig): Promise<T> {
  return await axios.get(url, { ...options });
}

async function _post(url: string, data?: any) {
  const response = await axios.post(url, JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
  });
  return response.data;
}

async function _postMultiPart(url: string, formData: FormData, options?: AxiosRequestConfig) {
  const response = await axios.post(url, formData, {
    ...options,
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

async function _postTTS(url: string, formData: FormData, options?: AxiosRequestConfig) {
  const response = await axios.post(url, formData, {
    ...options,
    headers: { 'Content-Type': 'multipart/form-data' },
    responseType: 'arraybuffer',
  });
  return response.data;
}

async function _put(url: string, data?: any) {
  const response = await axios.put(url, JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
  });
  return response.data;
}

async function _delete<T>(url: string): Promise<T> {
  const response = await axios.delete(url);
  return response.data;
}

async function _deleteWithOptions<T>(url: string, options?: AxiosRequestConfig): Promise<T> {
  const response = await axios.delete(url, { ...options });
  return response.data;
}

async function _patch(url: string, data?: any) {
  const response = await axios.patch(url, JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
  });
  return response.data;
}

/**
 * Caladon surgery (SURGERY.md §A3): the JWT refresh-token bearer flow is amputated. Identity is a
 * per-request `Authorization: Swifty …` header signed in WASM (see client AuthContext.signRequest
 * + useSSE). There is no refresh endpoint, no bearer to re-inject, no Mongo session to extend. A
 * 401 means clock skew (re-sign at the call site) or a locked seed (surface "re-unlock"); the
 * interceptor simply rejects so the UI can route to the seed-unlock screen.
 *
 * `refreshToken` / `dispatchTokenUpdatedEvent` remain as inert stubs only to preserve the default
 * export shape for legacy importers; they no longer touch a server or a bearer token.
 */
const refreshToken = (_retry?: boolean): Promise<t.TRefreshTokenResponse | undefined> =>
  Promise.resolve(undefined);

const dispatchTokenUpdatedEvent = (_token: string) => {
  /* no-op: Caladon has no bearer token to broadcast */
};

if (typeof window !== 'undefined') {
  axios.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (!error.response) {
        return Promise.reject(error);
      }
      // No refresh dance. Reject all errors (incl. 401) — the caller re-signs or re-unlocks.
      return Promise.reject(error);
    },
  );
}

export default {
  get: _get,
  getResponse: _getResponse,
  post: _post,
  postMultiPart: _postMultiPart,
  postTTS: _postTTS,
  put: _put,
  delete: _delete,
  deleteWithOptions: _deleteWithOptions,
  patch: _patch,
  refreshToken,
  dispatchTokenUpdatedEvent,
};
