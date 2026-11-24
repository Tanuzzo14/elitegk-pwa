// Elite GK · promemoria automatici
// Ogni 5 minuti chiama /api/cron dell'app: lì si decide chi va avvisato e si inviano le notifiche.
// Variabili: APP_URL (es. https://elitegk-pwa.pages.dev) · segreto CRON_KEY (lo stesso impostato su Pages).
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(run(env));
  },
  async fetch(req, env) {
    const u = new URL(req.url);
    if (u.pathname === "/run" && env.CRON_KEY && req.headers.get("x-cron") === env.CRON_KEY) {
      return new Response(await run(env), { headers: { "content-type": "application/json" } });
    }
    return new Response("Elite GK · promemoria attivi");
  }
};
async function run(env) {
  const r = await fetch(String(env.APP_URL || "").replace(/\/$/, "") + "/api/cron", {
    method: "POST",
    headers: { "x-cron": env.CRON_KEY, "content-type": "application/json" },
    body: "{}"
  });
  const t = await r.text();
  console.log("cron", r.status, t);
  return t;
}
