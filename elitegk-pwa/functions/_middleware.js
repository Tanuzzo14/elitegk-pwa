// Blocca l'accesso pubblico ai file tecnici del progetto (non servono al browser)
const HIDE=/^\/(cron-worker|lib)\/|^\/(schema\.sql|README\.md|wrangler\.toml|\.git)/i;
export async function onRequest({request,next}){
  const u=new URL(request.url);
  if(HIDE.test(u.pathname))return new Response("Not found",{status:404,headers:{"content-type":"text/plain"}});
  return next();
}
