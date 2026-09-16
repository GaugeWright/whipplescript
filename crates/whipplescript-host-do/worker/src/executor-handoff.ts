// Only the core's needs_executor outcome enters this private transport. Generic
// HTTP has no access to this callback and cannot upgrade itself by URL or body.
export type ExecutorHandoffRequest = {
  url: string;
  headers: [string, string][];
  body: unknown;
};

export async function performExecutorHandoff(
  request: ExecutorHandoffRequest,
  send: (url: string, init: RequestInit) => Promise<Response>,
  read: (response: Response) => Promise<unknown>,
): Promise<string> {
  const url = new URL(request.url);
  url.pathname = "/exec/invocation";
  url.search = "";
  url.hash = "";
  const response = await send(url.toString(), {
    method: "POST",
    headers: Object.fromEntries(request.headers),
    body: JSON.stringify(request.body),
  });
  return JSON.stringify({ status: response.status, body: await read(response) });
}
