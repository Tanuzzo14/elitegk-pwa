// Elite GK API - Cloudflare Pages Functions + D1 (binding: DB)
const J=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{"content-type":"application/json","cache-control":"no-store",...h}});
const E=new TextEncoder(),b64=u=>btoa(String.fromCharCode(...u)),ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const eq=(a,b)=>{a=E.encode(a);b=E.encode(b);let r=a.length^b.length;for(let i=0;i<a.length;i++)r|=a[i]^(b[i]||0);return r===0};
async function pb(pw,salt){const k=await crypto.subtle.importKey("raw",E.encode(pw),"PBKDF2",false,["deriveBits"]);return b64(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:100000},k,256)))}
const sha=async s=>b64(new Uint8Array(await crypto.subtle.digest("SHA-256",E.encode(s))));
async function mk(env,u,pw,prof){const s=crypto.getRandomValues(new Uint8Array(16));const r=await env.DB.prepare("INSERT INTO users(username,salt,hash,profile,created) VALUES(?,?,?,?,?)").bind(u,b64(s),await pb(pw,s),JSON.stringify(prof),Date.now()).run();return r.meta.last_row_id}
async function sess(env,uid){const t=b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g,"x");await env.DB.prepare("INSERT INTO sessions(th,uid,exp) VALUES(?,?,?)").bind(await sha(t),uid,Date.now()+30*864e5).run();return `sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`}
async function who(env,req){const m=/(?:^|; )sid=([^;]+)/.exec(req.headers.get("cookie")||"");if(!m)return null;return await env.DB.prepare("SELECT u.id,u.username,u.profile FROM sessions s JOIN users u ON u.id=s.uid WHERE s.th=? AND s.exp>?").bind(await sha(m[1]),Date.now()).first()}
export async function onRequest({request:req,env}){
 const url=new URL(req.url),p=url.pathname.replace(/^\/api\//,""),m=req.method;
 if(m!="GET"&&req.headers.get("origin")&&new URL(req.headers.get("origin")).host!==url.host)return J({e:"origin"},403);
 try{
  const body=m=="GET"?{}:await req.json().catch(()=>({}));
  const u=String(body.u||"").toLowerCase().trim(),pw=String(body.p||"");
  const adm=env.ADMIN_USER&&env.ADMIN_PASSWORD&&u===env.ADMIN_USER.toLowerCase();
  if(p=="login"&&m=="POST"){
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS login_fail(k TEXT PRIMARY KEY,n INTEGER NOT NULL,until INTEGER NOT NULL)").run();
   const ip=req.headers.get("cf-connecting-ip")||"?",keys=["u:"+u,"ip:"+ip],now=Date.now();
   for(const k of keys){const f=await env.DB.prepare("SELECT n,until FROM login_fail WHERE k=?").bind(k).first();if(f&&f.until>now)return J({e:"Troppi tentativi. Riprova tra "+Math.ceil((f.until-now)/60000)+" minuti."},429)}
   const fail=async()=>{for(const k of keys){const lim=k[0]=="u"?5:20;const f=await env.DB.prepare("SELECT n FROM login_fail WHERE k=?").bind(k).first();const n=(f?f.n:0)+1;await env.DB.prepare("INSERT INTO login_fail(k,n,until) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=excluded.n,until=excluded.until").bind(k,n>=lim?0:n,n>=lim?now+15*60000:0).run()}};
   let row=await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(u).first(),ok=false;
   if(adm){ok=eq(pw,env.ADMIN_PASSWORD);if(ok&&!row){await mk(env,u,crypto.randomUUID(),{sport:true,team:[1,4],match:0});row=await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(u).first()}}
   else if(row)ok=eq(await pb(pw,ub(row.salt)),row.hash);
   if(!ok){await fail();return J({e:"Credenziali errate"},401)}
   await env.DB.prepare("DELETE FROM login_fail WHERE k=?").bind("u:"+u).run();
   return J({ok:1},200,{"set-cookie":await sess(env,row.id)});
  }
  if(p=="register"&&m=="POST"){
   if(env.REGISTRATION=="closed")return J({e:"Registrazioni chiuse"},403);
   if(!/^[a-z0-9_.-]{3,32}$/.test(u)||pw.length<8)return J({e:"Utente 3-32 caratteri (a-z, 0-9, . _ -), password minimo 8"},400);
   if(adm||await env.DB.prepare("SELECT 1 FROM users WHERE username=?").bind(u).first())return J({e:"Utente non disponibile"},409);
   const id=await mk(env,u,pw,{sport:!!body.sport,team:[1,4],match:0});
   return J({ok:1},200,{"set-cookie":await sess(env,id)});
  }
  if(p=="waitlist"&&m=="POST"){
   if(body.website)return J({ok:1});
   const t=(k,n)=>String(body[k]||"").trim().slice(0,n);
   const w={name:t("name",80),contact:t("contact",120),role:t("role",10),city:t("city",60),clients:t("clients",20),price:t("price",20),model:t("model",30),tools:t("tools",120),note:t("note",400),follow:t("follow",60),pain:t("pain",240),hours:t("hours",20),pilot:t("pilot",40),interview:t("interview",20)};
   if(!w.name||!w.contact)return J({e:"Inserisci nome e un contatto."},400);
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS waitlist(id INTEGER PRIMARY KEY AUTOINCREMENT,created INTEGER NOT NULL,name TEXT,contact TEXT NOT NULL UNIQUE,role TEXT,city TEXT,clients TEXT,price TEXT,model TEXT,tools TEXT,note TEXT)").run();
   for(const c of ["follow","pain","hours","pilot","interview"]){try{await env.DB.prepare(`ALTER TABLE waitlist ADD COLUMN ${c} TEXT`).run()}catch(e){}}
   await env.DB.prepare("INSERT INTO waitlist(created,name,contact,role,city,clients,price,model,tools,note,follow,pain,hours,pilot,interview) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(contact) DO UPDATE SET name=excluded.name,role=excluded.role,city=excluded.city,clients=excluded.clients,price=excluded.price,model=excluded.model,tools=excluded.tools,note=excluded.note,follow=excluded.follow,pain=excluded.pain,hours=excluded.hours,pilot=excluded.pilot,interview=excluded.interview").bind(Date.now(),w.name,w.contact,w.role,w.city,w.clients,w.price,w.model,w.tools,w.note,w.follow,w.pain,w.hours,w.pilot,w.interview).run();
   return J({ok:1});
  }
  const me=await who(env,req);if(!me)return J({e:"auth"},401);
  const isAdm=!!(env.ADMIN_USER&&me.username===env.ADMIN_USER.toLowerCase());
  if(p=="waitlist"&&m=="GET"){if(!isAdm)return J({e:"nf"},404);let rows=[];try{rows=(await env.DB.prepare("SELECT * FROM waitlist ORDER BY created DESC").all()).results||[]}catch(e){}
   if(url.searchParams.get("csv")){const c=["data","nome","contatto","ruolo","citta","clienti","strumenti","come_segue","difficolta","ore_settimana","prezzo_mese","modello","pilota","intervista","note"],q=v=>'"'+String(v??"").replace(/"/g,'""')+'"';const lines=[c.join(";")].concat(rows.map(r=>[new Date(r.created).toISOString().slice(0,16).replace("T"," "),r.name,r.contact,r.role,r.city,r.clients,r.tools,r.follow,r.pain,r.hours,r.price,r.model,r.pilot,r.interview,r.note].map(q).join(";")));return new Response("\ufeff"+lines.join("\n"),{headers:{"content-type":"text/csv; charset=utf-8","content-disposition":"attachment; filename=lista-attesa-pro.csv","cache-control":"no-store"}})}
   return J({rows})}
  if(p=="me"){const s=await env.DB.prepare("SELECT data FROM state WHERE uid=?").bind(me.id).first();return J({user:{username:me.username,admin:isAdm},profile:JSON.parse(me.profile),state:s?JSON.parse(s.data):{}})}
  if(p=="state"&&m=="PUT"){const d=JSON.stringify(body);if(d.length>200000)return J({e:"big"},413);await env.DB.prepare("INSERT INTO state(uid,data,updated) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data,updated=excluded.updated").bind(me.id,d,Date.now()).run();return J({ok:1})}
  if(p=="profile"&&m=="PUT"){const pr={sport:!!body.sport,team:(Array.isArray(body.team)?body.team:[]).map(Number).filter(n=>n>=0&&n<7).slice(0,2),match:Number.isInteger(body.match)&&body.match>=-1&&body.match<7?body.match:-1};await env.DB.prepare("UPDATE users SET profile=? WHERE id=?").bind(JSON.stringify(pr),me.id).run();return J({ok:1})}
  if(p=="logout"&&m=="POST"){const c=/(?:^|; )sid=([^;]+)/.exec(req.headers.get("cookie")||"");if(c)await env.DB.prepare("DELETE FROM sessions WHERE th=?").bind(await sha(c[1])).run();return J({ok:1},200,{"set-cookie":"sid=; Path=/; Max-Age=0"})}
  return J({e:"nf"},404);
 }catch(e){return J({e:"server"},500)}
}
