// Elite GK API - Cloudflare Pages Functions + D1 (binding: DB)
import {buildPushHTTPRequest} from "../../lib/pushforge.js";
const J=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"same-origin",...h}});
// ---- Sicurezza
// SQL: tutte le query usano parametri (bind), mai testo dell'utente concatenato.
// cln: pulisce ricorsivamente ciò che arriva dagli utenti prima di salvarlo: niente HTML, apici o codice
// può finire nelle schermate di un altro utente (cliente → professionista e viceversa).
const KEY=/^[^<>"'`\\\u0000-\u001f]{1,80}$/;
function cln(v,d=0){if(d>14)return null;if(typeof v=="string")return v.slice(0,4000).replace(/[<>`\\'"]/g,c=>({"<":"‹",">":"›","`":"’","\\":"/","'":"’",'"':"”"}[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g,"");
 if(typeof v=="number")return Number.isFinite(v)?v:0;if(typeof v=="boolean"||v===null)return v;if(Array.isArray(v))return v.slice(0,5000).map(x=>cln(x,d+1));
 if(typeof v=="object"){const o={};let n=0;for(const k of Object.keys(v)){if(!KEY.test(k)||k=="__proto__"||k=="constructor"||k=="prototype")continue;if(++n>5000)break;o[k]=cln(v[k],d+1)}return o}return null}
// limite di richieste per chiave (ip o utente) in una finestra di tempo
async function rl(env,k,max,win){const now=Date.now();await env.DB.prepare("CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY,n INTEGER,t INTEGER)").run();const r=await env.DB.prepare("SELECT n,t FROM rl WHERE k=?").bind(k).first();
 if(!r||now-r.t>win){await env.DB.prepare("INSERT INTO rl(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=1,t=excluded.t").bind(k,now).run();return true}if(r.n>=max)return false;await env.DB.prepare("UPDATE rl SET n=n+1 WHERE k=?").bind(k).run();return true}
// registro delle azioni sensibili (chi, cosa, quando), senza dati sanitari
async function aud(env,uid,act,tgt){try{await env.DB.prepare("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER,uid INTEGER,act TEXT,tgt TEXT)").run();await env.DB.prepare("INSERT INTO audit(at,uid,act,tgt) VALUES(?,?,?,?)").bind(Date.now(),uid||0,String(act).slice(0,40),String(tgt??"").slice(0,80)).run()}catch(e){}}
// le notifiche push si inviano solo ai server ufficiali dei browser (niente indirizzi arbitrari)
const PUSHH=/^https:\/\/([a-z0-9-]+\.)*(fcm\.googleapis\.com|android\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)\//;
const csv=v=>{v=String(v??"");return /^[=+\-@\t\r]/.test(v)?"'"+v:v};

const E=new TextEncoder(),b64=u=>btoa(String.fromCharCode(...u)),ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const eq=(a,b)=>{a=E.encode(a);b=E.encode(b);let r=a.length^b.length;for(let i=0;i<a.length;i++)r|=a[i]^(b[i]||0);return r===0};
async function pb(pw,salt){const k=await crypto.subtle.importKey("raw",E.encode(pw),"PBKDF2",false,["deriveBits"]);return b64(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:100000},k,256)))}
const sha=async s=>b64(new Uint8Array(await crypto.subtle.digest("SHA-256",E.encode(s))));
async function mk(env,u,pw,prof){const s=crypto.getRandomValues(new Uint8Array(16));const r=await env.DB.prepare("INSERT INTO users(username,salt,hash,profile,created) VALUES(?,?,?,?,?)").bind(u,b64(s),await pb(pw,s),JSON.stringify(prof),Date.now()).run();return r.meta.last_row_id}
async function sess(env,uid){const t=b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g,"x");await env.DB.prepare("INSERT INTO sessions(th,uid,exp) VALUES(?,?,?)").bind(await sha(t),uid,Date.now()+30*864e5).run();return `sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`}
async function who(env,req){const m=/(?:^|; )sid=([^;]+)/.exec(req.headers.get("cookie")||"");if(!m)return null;return await env.DB.prepare("SELECT u.id,u.username,u.profile FROM sessions s JOIN users u ON u.id=s.uid WHERE s.th=? AND s.exp>?").bind(await sha(m[1]),Date.now()).first()}
let ready=false;
async function tables(env){if(ready)return;for(const q of["CREATE TABLE IF NOT EXISTS pros(uid INTEGER PRIMARY KEY,name TEXT,roles TEXT,created INTEGER)",
 "CREATE TABLE IF NOT EXISTS links(pro INTEGER NOT NULL,client INTEGER NOT NULL,scope TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'on',created INTEGER,PRIMARY KEY(pro,client))",
 "CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY,pro INTEGER NOT NULL,scope TEXT NOT NULL,label TEXT,created INTEGER,used_by INTEGER,used_at INTEGER)",
 "CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,pro INTEGER NOT NULL,client INTEGER NOT NULL,dir TEXT NOT NULL,kind TEXT,text TEXT,created INTEGER,seen INTEGER DEFAULT 0)",
 "CREATE TABLE IF NOT EXISTS push_subs(endpoint TEXT PRIMARY KEY,uid INTEGER NOT NULL,p256dh TEXT,auth TEXT,created INTEGER)"])await env.DB.prepare(q).run();for(const q of["ALTER TABLE links ADD COLUMN pause_by TEXT","ALTER TABLE links ADD COLUMN sub TEXT","ALTER TABLE links ADD COLUMN info TEXT","ALTER TABLE invites ADD COLUMN data TEXT"])try{await env.DB.prepare(q).run()}catch(e){}ready=true}
const SC=v=>["w","m","wm"].includes(v)?v:"wm";
const code=()=>b64(crypto.getRandomValues(new Uint8Array(9))).replace(/[+/=]/g,"").slice(0,10);
// dati del cliente filtrati per ambito: il professionista vede solo ciò che gli serve, mai il diario
function forPro(data,scope){let s={};try{s=JSON.parse(data||"{}")}catch(e){}for(const d in s.log||{}){const g=s.log[d];if(!g)continue;delete g.j;if(scope=="w"){delete g.m;delete g.x}if(scope=="m"){delete g.e;delete g.ws}}if(scope=="m")s.lg={};delete s.sp;delete s.rm;return s}
async function proOf(env,uid){return await env.DB.prepare("SELECT * FROM pros WHERE uid=?").bind(uid).first()}
async function push(env,uid,title,body,path,host){if(!env.VAPID_PRIVATE_KEY)return 0;let jwk;try{jwk=JSON.parse(env.VAPID_PRIVATE_KEY)}catch(e){return 0}
 const subs=(await env.DB.prepare("SELECT * FROM push_subs WHERE uid=?").bind(uid).all()).results||[];let n=0;
 for(const x of subs){try{const r=await buildPushHTTPRequest({privateJWK:jwk,subscription:{endpoint:x.endpoint,keys:{p256dh:x.p256dh,auth:x.auth}},message:{payload:{web_push:8030,notification:{title,body,navigate:"https://"+host+(path||"/"),lang:"it",dir:"ltr"}},adminContact:env.PUSH_CONTACT||"https://"+host,options:{ttl:86400,urgency:"normal"}}});
  const res=await fetch(r.endpoint,{method:"POST",headers:r.headers,body:r.body});if(res.status==404||res.status==410)await env.DB.prepare("DELETE FROM push_subs WHERE endpoint=?").bind(x.endpoint).run();else if(res.ok)n++}catch(e){}}
 return n}
const SPK=/^[a-z0-9_]{2,30}$/,DT=/^\d{4}-\d{2}-\d{2}$/;
function SUB(b){if(!b||typeof b!="object")return null;const price=Math.max(0,Math.min(100000,Math.round((parseFloat(String(b.price).replace(",","."))||0)*100)/100)),per=b.per=="p"?"p":"m",n=Math.max(1,Math.min(104,parseInt(b.n)||1)),u=b.u=="w"?"w":"m";
 const start=DT.test(String(b.start))?String(b.start):new Date().toISOString().slice(0,10);let end=DT.test(String(b.end))?String(b.end):null;if(!end){const d=new Date(start+"T12:00:00Z");if(u=="w")d.setUTCDate(d.getUTCDate()+7*n);else d.setUTCMonth(d.getUTCMonth()+n);d.setUTCDate(d.getUTCDate()-1);end=d.toISOString().slice(0,10)}return{price,per,n,u,start,end}}
function INF(b){b=b||{};return{name:String(b.name||"").slice(0,60),goal:String(b.goal||"").slice(0,200),lim:String(b.lim||"").slice(0,300)}}
const today0=()=>new Date(Date.now()+36e5).toISOString().slice(0,10),expd=s=>{try{const o=JSON.parse(s||"null");return!!(o&&o.end&&o.end<today0())}catch(e){return false}};
function mergePlan(o,np,scope){if(!(o.plan&&typeof o.plan=="object")||scope=="wm")return np;const out={...o.plan},keep=scope=="w"?["ex","sessions","week","weeks","prog","sem","tests","gk","wkt"]:["meals","ml","sw","mac","sup","shop","kcal"];keep.forEach(k=>{if(k in np)out[k]=np[k]});["name","info","goals","focus","reward","rt"].forEach(k=>{if(k in np)out[k]=np[k]});return out}
const HB=h=>(Array.isArray(h)?h:[]).slice(0,20).map(x=>({id:String(x.id||"h"+Math.random().toString(36).slice(2,7)).slice(0,12),n:String(x.n||"Abitudine").slice(0,44),i:String(x.i||"✳️").slice(0,4)}));
function PRF(b){b=b||{};const nt=Math.min(6,Math.max(1,parseInt(b.nt)||2)),team=[...new Set((Array.isArray(b.team)?b.team:[]).map(Number).filter(n=>Number.isInteger(n)&&n>=0&&n<7))].slice(-nt);
 const mt=[...new Set((Array.isArray(b.mt)?b.mt:Number.isInteger(b.match)&&b.match>=0?[b.match]:[]).map(Number).filter(n=>Number.isInteger(n)&&n>=0&&n<7&&!team.includes(n)))].slice(0,4);
 const HM=/^\d{1,2}:\d{2}$/,tm=o=>{const r={};if(o&&typeof o=="object")for(const k in o)if(/^[0-6]$/.test(k)&&HM.test(String(o[k])))r[k]=String(o[k]);return r},ov={};if(b.ov&&typeof b.ov=="object")for(const k in b.ov)if(/^[0-6]$/.test(k)&&/^[\w-]{1,30}$/.test(String(b.ov[k])))ov[k]=String(b.ov[k]);
 return{sport:!!b.sport,sp:SPK.test(String(b.sp||""))?String(b.sp):"futsal",nt,team,mt,match:mt.length?mt[0]:-1,tt:tm(b.tt),mtt:tm(b.mtt),ov}}
const AR=s=>s=="wm"?["w","m"]:[s],ARN={w:"l’allenamento",m:"l’alimentazione"},sub=(s,x)=>{const r=AR(s).filter(k=>!AR(x).includes(k));return r.length==2?"wm":r[0]||null};
async function clash(env,client,pro,scope){const L=(await env.DB.prepare("SELECT l.pro,l.scope,p.name FROM links l JOIN pros p ON p.uid=l.pro WHERE l.client=? AND l.pro<>? AND l.status='on'").bind(client,pro).all()).results||[];
 return L.filter(l=>AR(l.scope).some(k=>AR(scope).includes(k))).map(l=>({pro:l.pro,name:l.name,scope:l.scope,areas:AR(l.scope).filter(k=>AR(scope).includes(k))}))}
async function cede(env,client,cl,scope,who,host){for(const c of cl){const ns=sub(c.scope,scope);if(ns)await env.DB.prepare("UPDATE links SET scope=? WHERE pro=? AND client=?").bind(ns,c.pro,client).run();else await env.DB.prepare("UPDATE links SET status='off',pause_by='c' WHERE pro=? AND client=?").bind(c.pro,client).run();
 await push(env,c.pro,"Cambio nel team","@"+who+" ha affidato "+c.areas.map(k=>ARN[k]).join(" e ")+" a un altro professionista.","/?pro=1",host)}}
export async function onRequest({request:req,env}){
 const url=new URL(req.url),p=url.pathname.replace(/^\/api\//,""),m=req.method;
 if(m!="GET"&&req.headers.get("origin")&&new URL(req.headers.get("origin")).host!==url.host)return J({e:"origin"},403);
 if(m!="GET"&&req.headers.get("sec-fetch-site")=="cross-site")return J({e:"origin"},403);
 if(+(req.headers.get("content-length")||0)>400000)return J({e:"big"},413);
 const ip=req.headers.get("cf-connecting-ip")||"x";
 try{
  let body=m=="GET"?{}:await req.json().catch(()=>({}));if(!body||typeof body!="object"||Array.isArray(body))body={};{const pw0=body.p;body=cln(body)||{};if(pw0!==undefined)body.p=typeof pw0=="string"?pw0.slice(0,200):""}
  if(p=="cron"){if(!env.CRON_KEY||!eq(String(req.headers.get("x-cron")||""),env.CRON_KEY))return J({e:"no"},403);await tables(env);
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS rem_sent(uid INTEGER NOT NULL,id TEXT NOT NULL,at INTEGER,PRIMARY KEY(uid,id))").run();
   const now=Date.now(),rows=(await env.DB.prepare("SELECT uid,data FROM state WHERE uid IN (SELECT DISTINCT uid FROM push_subs)").all()).results||[];let n=0,due=0;
   for(const r of rows){let o;try{o=JSON.parse(r.data)}catch(e){continue}
    for(const x of(Array.isArray(o.rm)?o.rm:[])){if(!x||!(x.at<=now&&x.at>now-20*60000))continue;const g=(o.log||{})[x.ds]||{};
     if(x.k=="wo"&&(g.ws||(g.e&&Object.values(g.e).some(Boolean))))continue;if(x.k=="jd"&&g.jd)continue;if(x.k=="m"&&g.m&&g.m[x.s])continue;if(x.k=="su"&&g.su&&g.su[x.s])continue;if(x.k=="rt"&&g.rt&&g.rt[x.s])continue;
     const ins=await env.DB.prepare("INSERT OR IGNORE INTO rem_sent(uid,id,at) VALUES(?,?,?)").bind(r.uid,String(x.id),now).run();if(!ins.meta||!ins.meta.changes)continue;
     due++;n+=await push(env,r.uid,String(x.t||"Zeno 🐇").slice(0,90),String(x.b||"").slice(0,220),String(x.p||"/").startsWith("/")?x.p:"/",env.APP_HOST||url.host)}}
   await env.DB.prepare("DELETE FROM rem_sent WHERE at<?").bind(now-3*864e5).run();await env.DB.prepare("DELETE FROM sessions WHERE exp<?").bind(now).run();try{await env.DB.prepare("DELETE FROM rl WHERE t<?").bind(now-864e5).run();await env.DB.prepare("DELETE FROM audit WHERE at<?").bind(now-365*864e5).run()}catch(e){}return J({ok:1,users:rows.length,due,sent:n})}
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
   await aud(env,row.id,"login",ip);return J({ok:1},200,{"set-cookie":await sess(env,row.id)});
  }
  if(p=="invite"&&m=="GET"){await tables(env);if(!await rl(env,"ig:"+ip,60,36e5))return J({e:"Troppe richieste"},429);const i=await env.DB.prepare("SELECT i.scope,i.used_by,i.data,p.name FROM invites i JOIN pros p ON p.uid=i.pro WHERE i.code=?").bind(String(url.searchParams.get("c")||"")).first();let d={};try{d=JSON.parse(i&&i.data||"{}")||{}}catch(e){}return i&&!i.used_by?J({ok:1,name:i.name,scope:i.scope,user:d.user||"",cname:(d.info&&d.info.name)||"",ready:!!d.plan,sub:d.sub?{n:d.sub.n,u:d.sub.u,start:d.sub.start,end:d.sub.end}:null}):J({e:"Invito non valido o già usato"},404)}
  if(p=="register"&&m=="POST"){await tables(env);if(!await rl(env,"reg:"+ip,10,36e5))return J({e:"Troppi tentativi. Riprova più tardi."},429);
   let invOk=false;if(body.inv){await tables(env);invOk=!!await env.DB.prepare("SELECT 1 FROM invites WHERE code=? AND used_by IS NULL").bind(String(body.inv)).first()}
   if(env.REGISTRATION=="closed"&&!invOk)return J({e:"Registrazioni chiuse"},403);
   if(!/^[a-z0-9_.-]{3,32}$/.test(u)||pw.length<8)return J({e:"Utente 3-32 caratteri (a-z, 0-9, . _ -), password minimo 8"},400);
   if(adm||await env.DB.prepare("SELECT 1 FROM users WHERE username=?").bind(u).first())return J({e:"Utente non disponibile"},409);
   const id=await mk(env,u,pw,PRF({sport:!!body.sport,sp:"futsal",nt:2,team:[1,4],match:0}));
   await aud(env,id,"register",ip);return J({ok:1},200,{"set-cookie":await sess(env,id)});
  }
  if(p=="waitlist"&&m=="POST"){if(!await rl(env,"wl:"+ip,20,36e5))return J({e:"Troppe richieste. Riprova più tardi."},429);
   if(body.website)return J({ok:1});
   const t=(k,n)=>String(body[k]||"").trim().slice(0,n);
   const w={name:t("name",80),contact:t("contact",120),role:t("role",10),city:t("city",60),clients:t("clients",20),price:t("price",20),model:t("model",30),tools:t("tools",120),note:t("note",400),follow:t("follow",60),pain:t("pain",240),hours:t("hours",20),pilot:t("pilot",40),interview:t("interview",20),src:t("src",40)};
   if(!w.name||!w.contact)return J({e:"Inserisci nome e un contatto."},400);
   await env.DB.prepare("CREATE TABLE IF NOT EXISTS waitlist(id INTEGER PRIMARY KEY AUTOINCREMENT,created INTEGER NOT NULL,name TEXT,contact TEXT NOT NULL UNIQUE,role TEXT,city TEXT,clients TEXT,price TEXT,model TEXT,tools TEXT,note TEXT)").run();
   for(const c of ["follow","pain","hours","pilot","interview","src"]){try{await env.DB.prepare(`ALTER TABLE waitlist ADD COLUMN ${c} TEXT`).run()}catch(e){}}
   await env.DB.prepare("INSERT INTO waitlist(created,name,contact,role,city,clients,price,model,tools,note,follow,pain,hours,pilot,interview,src) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(contact) DO UPDATE SET name=excluded.name,role=excluded.role,city=excluded.city,clients=excluded.clients,price=excluded.price,model=excluded.model,tools=excluded.tools,note=excluded.note,follow=excluded.follow,pain=excluded.pain,hours=excluded.hours,pilot=excluded.pilot,interview=excluded.interview,src=COALESCE(NULLIF(waitlist.src,''),excluded.src)").bind(Date.now(),w.name,w.contact,w.role,w.city,w.clients,w.price,w.model,w.tools,w.note,w.follow,w.pain,w.hours,w.pilot,w.interview,w.src).run();
   return J({ok:1});
  }
  const me=await who(env,req);if(!me)return J({e:"auth"},401);
  const isAdm=!!(env.ADMIN_USER&&me.username===env.ADMIN_USER.toLowerCase());
  if(p=="waitlist"&&m=="GET"){if(!isAdm)return J({e:"nf"},404);let rows=[];try{rows=(await env.DB.prepare("SELECT * FROM waitlist ORDER BY created DESC").all()).results||[]}catch(e){}
   if(url.searchParams.get("csv")){const c=["data","nome","contatto","ruolo","citta","clienti","strumenti","come_segue","difficolta","ore_settimana","prezzo_mese","modello","pilota","intervista","provenienza","note"],q=v=>'"'+csv(v).replace(/"/g,'""')+'"';const lines=[c.join(";")].concat(rows.map(r=>[new Date(r.created).toISOString().slice(0,16).replace("T"," "),r.name,r.contact,r.role,r.city,r.clients,r.tools,r.follow,r.pain,r.hours,r.price,r.model,r.pilot,r.interview,r.src,r.note].map(q).join(";")));return new Response("\ufeff"+lines.join("\n"),{headers:{"content-type":"text/csv; charset=utf-8","content-disposition":"attachment; filename=lista-attesa-pro.csv","cache-control":"no-store"}})}
   return J({rows})}
  await tables(env);
  if(p=="me"){const s=await env.DB.prepare("SELECT data FROM state WHERE uid=?").bind(me.id).first(),pr=await proOf(env,me.id);
   const pros=(await env.DB.prepare("SELECT l.pro,l.scope,l.status,l.sub,p.name,p.roles,(SELECT COUNT(*) FROM notes n WHERE n.pro=l.pro AND n.client=l.client AND n.dir='p2c' AND n.seen=0) un FROM links l JOIN pros p ON p.uid=l.pro WHERE l.client=? AND l.pro<>l.client").bind(me.id).all()).results||[];
   return J({user:{username:me.username,admin:isAdm,pro:pr?{name:pr.name,roles:pr.roles}:null,canPro:isAdm},profile:JSON.parse(me.profile),state:s?JSON.parse(s.data):{},pros,push:!!env.VAPID_PRIVATE_KEY})}
  // ---- notifiche push
  if(p=="push/key"){if(!env.VAPID_PRIVATE_KEY)return J({e:"off"},404);const k=JSON.parse(env.VAPID_PRIVATE_KEY),u8=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0)),raw=new Uint8Array([4,...u8(k.x),...u8(k.y)]);return J({key:b64(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")})}
  if(p=="push/sub"&&m=="POST"){const e=String(body.endpoint||""),k=body.keys||{};if(!PUSHH.test(e)||e.length>800||!k.p256dh||!k.auth||String(k.p256dh).length>200||String(k.auth).length>100)return J({e:"bad"},400);await env.DB.prepare("INSERT INTO push_subs(endpoint,uid,p256dh,auth,created) VALUES(?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET uid=excluded.uid,p256dh=excluded.p256dh,auth=excluded.auth").bind(e,me.id,String(k.p256dh),String(k.auth),Date.now()).run();return J({ok:1})}
  if(p=="push/unsub"&&m=="POST"){await env.DB.prepare("DELETE FROM push_subs WHERE endpoint=? AND uid=?").bind(String(body.endpoint||""),me.id).run();return J({ok:1})}
  if(p=="push/test"&&m=="POST"){const n=await push(env,me.id,"Zeno 🐇","Le notifiche funzionano. Ci sentiamo quando c’è qualcosa da fare.","/",url.host);return J({ok:1,n})}
  // ---- inviti: il cliente accetta
  if(p=="invite/accept"&&m=="POST"){await aud(env,me.id,"invite/accept",body.code);const i=await env.DB.prepare("SELECT * FROM invites WHERE code=?").bind(String(body.code||"")).first();if(!i||i.used_by)return J({e:"Invito non valido o già usato"},404);if(i.pro==me.id)return J({e:"Non puoi accettare un tuo invito"},400);
   const cl=await clash(env,me.id,i.pro,i.scope);if(cl.length&&!body.replace)return J({e:"conflict",conflict:cl.map(c=>({name:c.name,areas:c.areas}))},409);if(cl.length)await cede(env,me.id,cl,i.scope,me.username,url.host);
   await env.DB.prepare("INSERT INTO links(pro,client,scope,status,created) VALUES(?,?,?,'on',?) ON CONFLICT(pro,client) DO UPDATE SET scope=excluded.scope,status='on',pause_by=NULL").bind(i.pro,me.id,i.scope,Date.now()).run();
   await env.DB.prepare("UPDATE invites SET used_by=?,used_at=? WHERE code=?").bind(me.id,Date.now(),i.code).run();
   let d=null;try{d=JSON.parse(i.data||"null")}catch(e){}
   if(d){const pr0=await proOf(env,i.pro);if(d.sub||d.info)await env.DB.prepare("UPDATE links SET sub=?,info=? WHERE pro=? AND client=?").bind(d.sub?JSON.stringify(SUB(d.sub)):null,JSON.stringify(INF(d.info)),i.pro,me.id).run();
    if(d.profile&&i.scope!="m")await env.DB.prepare("UPDATE users SET profile=? WHERE id=?").bind(JSON.stringify(PRF(d.profile)),me.id).run();
    if(d.plan&&typeof d.plan=="object"){const row=await env.DB.prepare("SELECT data FROM state WHERE uid=?").bind(me.id).first();let o={};try{o=JSON.parse(row?row.data:"{}")||{}}catch(e){}
     o.plan=mergePlan(o,d.plan,i.scope);o.planRev=(o.planRev||0)+1;o.planBy=pr0&&pr0.name;o.planAt=Date.now();if(Array.isArray(d.habits)&&d.habits.length){o.hb=HB(d.habits);o.planHb=o.planRev}if(!o.v)o.v=3;if(d.sub&&d.sub.start&&o.set){o.set.ps=o.set.ps||d.sub.start}
     await env.DB.prepare("INSERT INTO state(uid,data,updated) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data,updated=excluded.updated").bind(me.id,JSON.stringify(o),Date.now()).run()}}
   await push(env,i.pro,"Nuovo cliente","@"+me.username+" ha accettato il tuo invito.","/?pro=1",url.host);const pr=await proOf(env,i.pro);return J({ok:1,name:pr&&pr.name})}
  // ---- messaggi tra cliente e professionista
  if(p=="notes"&&m=="GET"){const r=(await env.DB.prepare("SELECT n.*,p.name FROM notes n JOIN pros p ON p.uid=n.pro WHERE n.client=? ORDER BY n.created DESC LIMIT 60").bind(me.id).all()).results||[];await env.DB.prepare("UPDATE notes SET seen=1 WHERE client=? AND dir='p2c'").bind(me.id).run();return J({notes:r})}
  if(p=="note"&&m=="POST"){if(!await rl(env,"nt:"+me.id,60,36e5))return J({e:"Hai inviato troppi messaggi: riprova tra poco"},429);const pro=Number(body.pro),l=await env.DB.prepare("SELECT * FROM links WHERE pro=? AND client=? AND status='on'").bind(pro,me.id).first();if(!l)return J({e:"nf"},404);
   const kind=["dolore","difficolta","domanda"].includes(body.kind)?body.kind:"domanda",text=String(body.text||"").trim().slice(0,500);if(!text)return J({e:"Scrivi un messaggio"},400);
   await env.DB.prepare("INSERT INTO notes(pro,client,dir,kind,text,created) VALUES(?,?,'c2p',?,?,?)").bind(pro,me.id,kind,text,Date.now()).run();
   await push(env,pro,(kind=="dolore"?"🔴 ":kind=="difficolta"?"🟠 ":"💬 ")+"@"+me.username,text.slice(0,120),"/?pro=1",url.host);return J({ok:1})}
  if(p=="link/stop"&&m=="POST"){await aud(env,me.id,"link/stop",body.pro);await env.DB.prepare("UPDATE links SET status='off',pause_by='c' WHERE pro=? AND client=?").bind(Number(body.pro),me.id).run();return J({ok:1})}
  // ---- account professionista
  if(p=="pro/activate"&&m=="POST"){if(!await rl(env,"pa:"+me.id,10,36e5))return J({e:"Troppi tentativi"},429);await aud(env,me.id,"pro/activate","");if(!(isAdm||(env.PRO_CODE&&eq(String(body.code||""),env.PRO_CODE))))return J({e:"Codice non valido"},403);
   const roles=(Array.isArray(body.roles)?body.roles:[]).filter(r=>r=="pt"||r=="nu").join(",")||"pt",name=String(body.name||me.username).trim().slice(0,60)||me.username;
   await env.DB.prepare("INSERT INTO pros(uid,name,roles,created) VALUES(?,?,?,?) ON CONFLICT(uid) DO UPDATE SET name=excluded.name,roles=excluded.roles").bind(me.id,name,roles,Date.now()).run();return J({ok:1})}
  if(p=="pro"||p.startsWith("pro/")){const pr=await proOf(env,me.id);if(!pr)return J({e:"nf"},404);
   if(p=="pro"&&m=="GET"){const cl=(await env.DB.prepare("SELECT l.client id,l.scope,l.status,l.pause_by pb,l.sub,l.info,l.created,(SELECT group_concat(p2.name||'|'||l2.scope,';') FROM links l2 JOIN pros p2 ON p2.uid=l2.pro WHERE l2.client=l.client AND l2.pro<>l.pro AND l2.status='on') team,u.username,u.profile,s.data,s.updated,(SELECT COUNT(*) FROM notes n WHERE n.pro=l.pro AND n.client=l.client AND n.dir='c2p' AND n.seen=0) un,(SELECT kind FROM notes n WHERE n.pro=l.pro AND n.client=l.client AND n.dir='c2p' AND n.seen=0 ORDER BY created DESC LIMIT 1) uk FROM links l JOIN users u ON u.id=l.client LEFT JOIN state s ON s.uid=l.client WHERE l.pro=? ORDER BY l.created").bind(me.id).all()).results||[];
    const inv=(await env.DB.prepare("SELECT code,scope,label,created,data FROM invites WHERE pro=? AND used_by IS NULL ORDER BY created DESC").bind(me.id).all()).results||[];
    return J({pro:{name:pr.name,roles:pr.roles},clients:cl.map(c=>({id:c.id,username:c.username,scope:c.scope,status:c.status,pb:c.pb,sub:JSON.parse(c.sub||"null"),info:JSON.parse(c.info||"null"),team:(c.team||"").split(";").filter(Boolean).map(x=>{const[n,s]=x.split("|");return{name:n,scope:s}}),since:c.created,updated:c.updated,un:c.un,uk:c.uk,profile:JSON.parse(c.profile||"{}"),state:forPro(c.data,c.scope)})),invites:inv.map(i=>{let d=null;try{d=JSON.parse(i.data||"null")}catch(e){}return{code:i.code,scope:i.scope,label:i.label,created:i.created,data:d}})})}
   const IDT=b=>{if(!b||typeof b!="object")return null;const d={user:String(b.user||"").toLowerCase().replace(/[^a-z0-9_.-]/g,"").slice(0,32),info:INF(b.info),sub:b.sub?SUB(b.sub):null,profile:b.profile?PRF(b.profile):null,habits:b.habits?HB(b.habits):null,plan:b.plan&&typeof b.plan=="object"&&typeof b.plan.name=="string"?b.plan:null};return JSON.stringify(d).length<160000?d:false};
   if(p=="pro/invite"&&m=="POST"){const d=IDT(body.data);if(d===false)return J({e:"Piano troppo grande"},413);if(d&&d.user&&await env.DB.prepare("SELECT 1 FROM users WHERE username=?").bind(d.user).first())d.user="";
    const c=code();await env.DB.prepare("INSERT INTO invites(code,pro,scope,label,created,data) VALUES(?,?,?,?,?,?)").bind(c,me.id,SC(body.scope),String(body.label||(d&&d.info.name)||"").trim().slice(0,40),Date.now(),d?JSON.stringify(d):null).run();return J({ok:1,code:c,user:d&&d.user})}
   if(p=="pro/invite/data"&&m=="POST"){const d=IDT(body.data);if(!d)return J({e:"Dati non validi"},400);const r=await env.DB.prepare("UPDATE invites SET data=?,label=COALESCE(NULLIF(?,''),label) WHERE code=? AND pro=? AND used_by IS NULL").bind(JSON.stringify(d),d.info.name,String(body.code||""),me.id).run();return r.meta&&r.meta.changes?J({ok:1}):J({e:"Invito non trovato"},404)}
   if(p=="pro/invite/del"&&m=="POST"){await env.DB.prepare("DELETE FROM invites WHERE code=? AND pro=? AND used_by IS NULL").bind(String(body.code||""),me.id).run();return J({ok:1})}
   if(p=="pro/grant"&&m=="POST"){if(!isAdm)return J({e:"Solo l’amministratore"},403);await aud(env,me.id,"pro/grant",body.u);const cu=await env.DB.prepare("SELECT id,username FROM users WHERE username=?").bind(String(body.u||"").toLowerCase().trim()).first();if(!cu)return J({e:"Utente non trovato"},404);
    const roles=(Array.isArray(body.roles)?body.roles:[]).filter(r=>r=="pt"||r=="nu").join(",")||"pt",name=String(body.name||cu.username).trim().slice(0,60)||cu.username;
    await env.DB.prepare("INSERT INTO pros(uid,name,roles,created) VALUES(?,?,?,?) ON CONFLICT(uid) DO UPDATE SET name=excluded.name,roles=excluded.roles").bind(cu.id,name,roles,Date.now()).run();
    await push(env,cu.id,"🧑‍🏫 Pannello Pro attivo","Apri l’app: in alto trovi il Pannello Pro per seguire i tuoi clienti.","/?pro=1",url.host);return J({ok:1})}
   if(p=="pro/self"&&m=="POST"){await env.DB.prepare("INSERT INTO links(pro,client,scope,status,created) VALUES(?,?,'wm','on',?) ON CONFLICT(pro,client) DO UPDATE SET status='on'").bind(me.id,me.id,Date.now()).run();return J({ok:1})}
   if(p=="pro/add"&&m=="POST"){if(!isAdm)return J({e:"Solo l’amministratore può collegare utenti senza invito"},403);await aud(env,me.id,"pro/add",body.u);const cu=await env.DB.prepare("SELECT id,username FROM users WHERE username=?").bind(String(body.u||"").toLowerCase().trim()).first();if(!cu)return J({e:"Utente non trovato"},404);
    const cl=await clash(env,cu.id,me.id,SC(body.scope));if(cl.length)return J({e:"Per "+[...new Set(cl.flatMap(c=>c.areas))].map(k=>ARN[k]).join(" e ")+" è già seguito da "+cl.map(c=>c.name).join(", ")+". Mandagli un invito: sceglierà lui."},409);
    await env.DB.prepare("INSERT INTO links(pro,client,scope,status,created) VALUES(?,?,?,'on',?) ON CONFLICT(pro,client) DO UPDATE SET scope=excluded.scope,status='on',pause_by=NULL").bind(me.id,cu.id,SC(body.scope),Date.now()).run();
    if(cu.id!=me.id)await push(env,cu.id,"🤝 "+pr.name,"Ora ti segue su Zeno Fit: lo trovi in Impostazioni › Il tuo team.","/",url.host);return J({ok:1})}
   const cid=Number(body.client||url.searchParams.get("c")),lk=await env.DB.prepare("SELECT * FROM links WHERE pro=? AND client=?").bind(me.id,cid).first();if(!lk)return J({e:"nf"},404);
   if(p=="pro/notes"&&m=="GET"){const r=(await env.DB.prepare("SELECT * FROM notes WHERE pro=? AND client=? ORDER BY created DESC LIMIT 60").bind(me.id,cid).all()).results||[];await env.DB.prepare("UPDATE notes SET seen=1 WHERE pro=? AND client=? AND dir='c2p'").bind(me.id,cid).run();return J({notes:r})}
   if(p=="pro/msg"&&m=="POST"){if(lk.status!="on")return J({e:"Collegamento non attivo"},400);if(!await rl(env,"pm:"+me.id,200,36e5))return J({e:"Troppi messaggi: riprova tra poco"},429);const text=String(body.text||"").trim().slice(0,500);if(!text)return J({e:"Scrivi un messaggio"},400);await env.DB.prepare("INSERT INTO notes(pro,client,dir,kind,text,created) VALUES(?,?,'p2c','msg',?,?)").bind(me.id,cid,text,Date.now()).run();
    await push(env,cid,"💬 "+pr.name,text.slice(0,120),"/?msg=1",url.host);return J({ok:1})}
   if(p=="pro/plan"&&m=="POST"){await aud(env,me.id,"pro/plan",cid);if(lk.status!="on")return J({e:"Collegamento in pausa"},400);if(expd(lk.sub))return J({e:"Abbonamento scaduto: rinnovalo per modificare il piano"},403);const np=body.plan;const raw=JSON.stringify(np||null);
    if(!np||typeof np!="object"||typeof np.name!="string"||raw.length>150000)return J({e:"Piano non valido"},400);
    const row=await env.DB.prepare("SELECT data FROM state WHERE uid=?").bind(cid).first();let o={};try{o=JSON.parse(row?row.data:"{}")}catch(e){}
    const out=mergePlan(o,np,lk.scope);
    o.plan=out;o.planRev=(o.planRev||0)+1;o.planBy=pr.name;o.planAt=Date.now();if(Array.isArray(body.habits)){o.hb=body.habits.slice(0,20).map(h=>({id:String(h.id||"h"+Math.random().toString(36).slice(2,7)).slice(0,12),n:String(h.n||"Abitudine").slice(0,44),i:String(h.i||"✳️").slice(0,4)}));o.planHb=o.planRev}
    if(!o.v){o.v=3}
    await env.DB.prepare("INSERT INTO state(uid,data,updated) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data,updated=excluded.updated").bind(cid,JSON.stringify(o),Date.now()).run();
    if(cid!=me.id)await push(env,cid,"📋 "+pr.name,"Ho aggiornato il tuo piano: aprilo per vedere le novità.","/",url.host);return J({ok:1,planRev:o.planRev})}
   if(p=="pro/profile"&&m=="POST"){await aud(env,me.id,"pro/profile",cid);if(lk.status!="on"||lk.scope=="m")return J({e:"Non segui l’allenamento di questo cliente"},403);await env.DB.prepare("UPDATE users SET profile=? WHERE id=?").bind(JSON.stringify(PRF(body)),cid).run();return J({ok:1})}
   if(p=="pro/sub"&&m=="POST"){await aud(env,me.id,"pro/sub",cid);const s=body.sub===null?null:SUB(body.sub);await env.DB.prepare("UPDATE links SET sub=?,info=COALESCE(?,info) WHERE pro=? AND client=?").bind(s?JSON.stringify(s):null,body.info?JSON.stringify(INF(body.info)):null,me.id,cid).run();
    if(s&&cid!=me.id&&body.notify)await push(env,cid,"✅ "+pr.name,"Percorso rinnovato"+(s.end?" fino al "+s.end.split("-").reverse().join("/"):"")+".","/",url.host);return J({ok:1})}
   if(p=="pro/link"&&m=="POST"){if(body.status=="off"){await env.DB.prepare("UPDATE links SET status='off',pause_by='p' WHERE pro=? AND client=?").bind(me.id,cid).run();return J({ok:1})}
    if(lk.pause_by=="c")return J({e:"Il cliente ha interrotto il collegamento: per riprendere mandagli un nuovo invito."},403);
    const cl=await clash(env,cid,me.id,lk.scope);if(cl.length)return J({e:"Nel frattempo "+cl.map(c=>c.name).join(", ")+" segue questo cliente per "+[...new Set(cl.flatMap(c=>c.areas))].map(k=>ARN[k]).join(" e ")+"."},409);
    await env.DB.prepare("UPDATE links SET status='on',pause_by=NULL WHERE pro=? AND client=?").bind(me.id,cid).run();return J({ok:1})}
   return J({e:"nf"},404)}
  if(p=="state"&&m=="PUT"){let back=null;const ex=await env.DB.prepare("SELECT data FROM state WHERE uid=?").bind(me.id).first();
   // se il professionista ha aggiornato il piano dopo l'ultima lettura del cliente, il piano del server vince
   if(ex){let o={};try{o=JSON.parse(ex.data)}catch(e){}if((o.planRev||0)>(body.planRev||0)){body.plan=o.plan;body.planRev=o.planRev;body.planBy=o.planBy;body.planAt=o.planAt;if(o.planHb){body.hb=o.hb;body.planHb=o.planHb}back={plan:o.plan,planRev:o.planRev,planBy:o.planBy,planAt:o.planAt,hb:o.planHb?o.hb:null}}}
   const d=JSON.stringify(body);if(d.length>200000)return J({e:"big"},413);await env.DB.prepare("INSERT INTO state(uid,data,updated) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data,updated=excluded.updated").bind(me.id,d,Date.now()).run();return J({ok:1,...(back||{})})}
  if(p=="profile"&&m=="PUT"){const pr=PRF(body);await env.DB.prepare("UPDATE users SET profile=? WHERE id=?").bind(JSON.stringify(pr),me.id).run();return J({ok:1})}
  if(p=="logout"&&m=="POST"){const c=/(?:^|; )sid=([^;]+)/.exec(req.headers.get("cookie")||"");if(c)await env.DB.prepare("DELETE FROM sessions WHERE th=?").bind(await sha(c[1])).run();return J({ok:1},200,{"set-cookie":"sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"})}
  return J({e:"nf"},404);
 }catch(e){return J({e:"server"},500)}
}
