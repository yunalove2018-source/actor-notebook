const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,PW=process.env.OWNER_PASSWORD,DIR=process.env.DATA_DIR||'./data';
if(!PW){console.error('OWNER_PASSWORD 환경변수를 설정하세요');process.exit(1)}
const SECRET=process.env.SECRET||crypto.createHash('sha256').update('s:'+PW).digest('hex');
fs.mkdirSync(DIR,{recursive:true});const F=path.join(DIR,'db.json');
let db={snapshot:null,invites:{},fb:[]};try{db=JSON.parse(fs.readFileSync(F))}catch(e){}db.fb=db.fb||[];
const save=()=>fs.writeFileSync(F,JSON.stringify(db));
const h=s=>crypto.createHash('sha256').update(s).digest('hex').slice(0,32);
const mac=m=>crypto.createHmac('sha256',SECRET).update(m).digest('hex');
const sign=(r,i,ms)=>{const m=r+'.'+i+'.'+(Date.now()+ms);return m+'.'+mac(m)};
const ok=t=>{const a=(t||'').split('.');if(a.length!=4)return null;const g=mac(a.slice(0,3).join('.'));return a[3].length==g.length&&crypto.timingSafeEqual(Buffer.from(a[3]),Buffer.from(g))&&+a[2]>Date.now()?{r:a[0],i:a[1]}:null};
const tries={};
const MIME={'.html':'text/html;charset=utf-8','.js':'text/javascript','.json':'application/json','.svg':'image/svg+xml','.webmanifest':'application/manifest+json'};
http.createServer((q,s)=>{
 s.setHeader('Access-Control-Allow-Origin','*');s.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');s.setHeader('Access-Control-Allow-Methods','POST, GET, OPTIONS');
 if(q.method=='OPTIONS'){s.writeHead(204);return s.end()}
 const send=(c,o)=>{s.writeHead(c,{'Content-Type':'application/json'});s.end(JSON.stringify(o))};
 if(q.method=='POST'&&q.url.startsWith('/api/')){let b='';q.on('data',d=>{b+=d;if(b.length>5e6)q.destroy()});q.on('end',()=>{let j={};try{j=JSON.parse(b||'{}')}catch(e){}
  const r=q.url.slice(5),A=ok((q.headers.authorization||'').replace('Bearer ',''));
  const ip=q.socket.remoteAddress+(q.headers['x-forwarded-for']||'');
  if(r=='login'||r=='redeem'){const n=tries[ip]=(tries[ip]||[]).filter(t=>t>Date.now()-6e5);if(n.length>=10)return send(429,{error:'잠시 후 다시 시도하세요'});n.push(Date.now())}
  if(r=='login')return j.password===PW?send(200,{token:sign('o','-',30*864e5)}):send(401,{error:'비밀번호가 달라요'});
  if(r=='redeem'){const v=db.invites[h(String(j.code||'').trim())];if(!v||v.used)return send(403,{error:'사용할 수 없는 코드예요'});if(!db.snapshot)return send(404,{error:'아직 공유된 기록이 없어요'});v.used=true;v.usedAt=Date.now();save();return send(200,{snapshot:db.snapshot,label:v.label,token:sign('g',h(String(j.code||'').trim()),864e5)})}
  if(!A)return send(401,{error:'로그인이 필요해요'});
  if(A.r=='g'&&!db.invites[A.i])return send(401,{error:'만료된 입장이에요'});
  if(r=='fb-list'&&A.r=='g')return send(200,{items:db.fb.filter(f=>f.inv==A.i)});
  if(r=='fb-save'&&A.r=='g'){const t=String(j.text||'').slice(0,2000);if(!t.trim())return send(400,{error:'내용을 적어 주세요'});
   if(j.id){const f=db.fb.find(x=>x.id==j.id&&x.inv==A.i);if(!f)return send(404,{error:'없는 글'});f.text=t;f.edited=Date.now()}
   else{if(db.fb.filter(x=>x.inv==A.i).length>=50)return send(429,{error:'너무 많아요'});db.fb.push({id:crypto.randomBytes(6).toString('hex'),inv:A.i,label:db.invites[A.i].label,text:t,at:Date.now()})}
   save();return send(200,{})}
  if(r=='fb-del'){const k=db.fb.findIndex(x=>x.id==j.id&&(A.r=='o'||x.inv==A.i));if(k>=0)db.fb.splice(k,1);save();return send(200,{})}
  if(A.r!='o')return send(403,{error:'권한이 없어요'});
  if(r=='fb-all')return send(200,{items:db.fb});
  if(r=='snapshot'){db.snapshot=j.data;save();return send(200,{})}
  if(r=='invite'){const c=String(j.code||'').trim();if(c.length<6)return send(400,{error:'코드는 6자 이상'});db.invites[h(c)]={label:String(j.label||'손님'),used:false,at:Date.now()};save();return send(200,{})}
  if(r=='invites')return send(200,{invites:Object.entries(db.invites).map(([id,v])=>({id,label:v.label,used:v.used}))});
  if(r=='invite-delete'){delete db.invites[j.id];save();return send(200,{})}
  send(404,{error:'없는 요청'})});return}
 const OKF=['index.html','config.js','manifest.webmanifest','sw.js','icon.svg','privacy.html'];let p=decodeURIComponent(q.url.split('?')[0]);if(p=='/')p='/index.html';const nm=p.slice(1);if(!OKF.includes(nm)){s.writeHead(404);return s.end('Not found')}const f=path.join(__dirname,nm);
 fs.readFile(f,(e,d)=>{if(e){s.writeHead(404);return s.end('Not found')}s.writeHead(200,{'Content-Type':MIME[path.extname(f)]||'application/octet-stream'});s.end(d)})
}).listen(PORT,()=>console.log('http://localhost:'+PORT));
