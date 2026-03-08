import { getSandbox } from "@cloudflare/sandbox";
export { Sandbox } from "@cloudflare/sandbox";

interface Env {
  Sandbox: any; // DurableObjectNamespace — typed by wrangler at deploy time
  API_TOKEN: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const auth = request.headers.get("Authorization");
    if (auth !== `Bearer ${env.API_TOKEN}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    const url = new URL(request.url);
    const sandboxId = url.searchParams.get("id") || "e2e-default";
    const sandbox = getSandbox(env.Sandbox, sandboxId);

    if (url.pathname === "/exec" && request.method === "POST") {
      const { command, cwd } = await request.json() as { command: string; cwd?: string };
      const result = await sandbox.exec(command, { cwd });
      return Response.json({
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        exitCode: result.exitCode,
      });
    }

    return new Response("Not found", { status: 404 });
  },
};
