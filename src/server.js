import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase, createCustomer, publicCustomer, warehouse, transaction } from './db.js';
import { token, digest, hashPassword, verifyPassword, fail, text, email, password, cookies } from './security.js';

const root = resolve(fileURLToPath(new URL('../public', import.meta.url)));
const wxKeys = ['WECHAT_MP_APP_ID', 'WECHAT_MP_APP_SECRET', 'WECHAT_WEB_APP_ID', 'WECHAT_WEB_APP_SECRET', 'WECHAT_CALLBACK_URL'];
const themeValues = ['blue', 'green', 'warm'];
const now = () => Date.now();

export function createApp({ db = openDatabase(), appUrl = process.env.APP_URL || 'http://127.0.0.1:3000', allowSetup = process.env.NODE_ENV !== 'production' && process.env.ALLOW_LOCAL_SETUP !== 'false' } = {}) {
  const secure = new URL(appUrl).protocol === 'https:';
  const attempts = new Map();
  function rate(req, key, limit = 15) {
    const k = `${req.socket.remoteAddress}:${key}`;
    const time = now();
    if (attempts.size > 10000) for (const [id, value] of attempts) if (value.until < time) attempts.delete(id);
    let row = attempts.get(k);
    if (!row || row.until < time) { row = { count: 0, until: time + 15 * 60 * 1000 }; attempts.set(k, row); }
    if (++row.count > limit) fail('操作过于频繁，请稍后再试', 429);
  }
  function config() {
    return Object.fromEntries(wxKeys.map(key => [key, db.prepare('SELECT value FROM settings WHERE key=?').get(key)?.value ?? process.env[key] ?? '']));
  }
  function wxStatus() {
    const c = config();
    return { mp: Boolean(c.WECHAT_MP_APP_ID && c.WECHAT_MP_APP_SECRET && c.WECHAT_CALLBACK_URL), web: Boolean(c.WECHAT_WEB_APP_ID && c.WECHAT_WEB_APP_SECRET && c.WECHAT_CALLBACK_URL) };
  }
  function audit(actor, customerId, action, detail = '') {
    db.prepare('INSERT INTO audit(actor_type,actor_id,customer_id,action,detail) VALUES(?,?,?,?,?)').run(actor?.staff_id ? 'staff' : actor?.customer_id ? 'customer' : 'system', actor?.staff_id || actor?.customer_id || null, customerId, action, detail);
  }
  function cookie(res, name, value, age) {
    const line = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure ? '; Secure' : ''}`;
    const existing = res.getHeader('Set-Cookie') || [];
    res.setHeader('Set-Cookie', [...(Array.isArray(existing) ? existing : [existing]), line]);
  }
  function getSession(req, type = 'customer') {
    const raw = cookies(req)[type === 'staff' ? 'bilin_staff' : 'bilin_customer'];
    if (!raw) return null;
    const s = db.prepare('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?').get(digest(raw), now());
    return s && s[type === 'staff' ? 'staff_id' : 'customer_id'] ? s : null;
  }
  function requireSession(req, type = 'customer') {
    const s = getSession(req, type);
    if (!s) fail('请先登录', 401);
    if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf-token'] !== s.csrf) fail('请求校验失败，请刷新页面重试', 403);
    return s;
  }
  function newSession(req, res, id, type = 'customer') {
    const previous = getSession(req, type);
    if (previous) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(previous.token_hash);
    const raw = token(), csrf = token();
    db.prepare('DELETE FROM sessions WHERE expires_at<?').run(now());
    db.prepare('INSERT INTO sessions(token_hash,customer_id,staff_id,csrf,expires_at,authenticated_at) VALUES(?,?,?,?,?,?)').run(digest(raw), type === 'customer' ? id : null, type === 'staff' ? id : null, csrf, now() + 7 * 86400000, now());
    cookie(res, type === 'staff' ? 'bilin_staff' : 'bilin_customer', raw, 7 * 86400);
    return csrf;
  }
  const json = (res, value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
  const redirect = (res, location) => { res.writeHead(302, { Location: location }); res.end(); };
  async function body(req) {
    if (!(req.headers['content-type'] || '').startsWith('application/json')) fail('请使用 JSON 请求', 415);
    let value = '';
    for await (const chunk of req) { value += chunk; if (value.length > 32768) fail('请求内容过大', 413); }
    try { const parsed = JSON.parse(value || '{}'); if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') fail('请求格式不正确'); return parsed; }
    catch { fail('请求格式不正确'); }
  }
  function ensureOrigin(req) {
    if (['GET', 'HEAD'].includes(req.method)) return;
    const origin = req.headers.origin;
    if (origin && origin !== new URL(appUrl).origin) fail('不允许跨站请求', 403);
    if (req.headers['sec-fetch-site'] === 'cross-site') fail('不允许跨站请求', 403);
  }
  function setupAllowed(req) {
    return allowSetup && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress) && !req.headers['x-forwarded-for'] && !db.prepare('SELECT id FROM staff LIMIT 1').get();
  }
  function profileInput(b) {
    return { nickname: text(b.nickname, '昵称', 60, true), phone: text(b.phone, '电话', 40), country: text(b.country, '常用目的国家', 80) };
  }
  function addressInput(b) {
    if (b.is_default !== undefined && typeof b.is_default !== 'boolean') fail('默认地址设置格式不正确');
    return { label: text(b.label, '地址标签', 40), recipient: text(b.recipient, '收件人', 100, true), phone: text(b.phone, '收件电话', 40, true), email: email(b.email),
      country: text(b.country, '国家', 80, true), province: text(b.province, '省州', 100), city: text(b.city, '城市', 100, true), postcode: text(b.postcode, '邮编', 30), street: text(b.street, '街道地址', 500, true), extra: text(b.extra, '补充地址', 300), is_default: b.is_default ? 1 : 0 };
  }
  function saveAddress(customerId, id, b) {
    const a = addressInput(b);
    return transaction(db, () => {
      if (id && !db.prepare('SELECT id FROM addresses WHERE id=? AND customer_id=?').get(id, customerId)) fail('地址不存在', 404);
      if (!db.prepare('SELECT id FROM addresses WHERE customer_id=?').get(customerId)) a.is_default = 1;
      if (a.is_default) db.prepare('UPDATE addresses SET is_default=0 WHERE customer_id=?').run(customerId);
      const values = [a.label,a.recipient,a.phone,a.email,a.country,a.province,a.city,a.postcode,a.street,a.extra,a.is_default];
      if (id) db.prepare('UPDATE addresses SET label=?,recipient=?,phone=?,email=?,country=?,province=?,city=?,postcode=?,street=?,extra=?,is_default=? WHERE id=? AND customer_id=?').run(...values,id,customerId);
      else id = Number(db.prepare('INSERT INTO addresses(label,recipient,phone,email,country,province,city,postcode,street,extra,is_default,customer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(...values,customerId).lastInsertRowid);
      if (!db.prepare('SELECT id FROM addresses WHERE customer_id=? AND is_default=1').get(customerId)) db.prepare('UPDATE addresses SET is_default=1 WHERE id=(SELECT id FROM addresses WHERE customer_id=? ORDER BY id LIMIT 1)').run(customerId);
      return db.prepare('SELECT * FROM addresses WHERE id=?').get(id);
    });
  }
  async function wechatGet(path, params) {
    const u = new URL(`https://api.weixin.qq.com/sns/${path}`);
    Object.entries(params).forEach(([key,value]) => u.searchParams.set(key,value));
    const r = await fetch(u, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) fail('微信服务暂时不可用，请稍后重试', 502);
    const data = await r.json();
    if (data.errcode) fail('微信授权失败，请重新登录或联系管理员检查配置', 502);
    return data;
  }
  const server = http.createServer(async (req,res) => {
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Referrer-Policy','same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    try {
      const url = new URL(req.url,appUrl), path = url.pathname, method = req.method;
      ensureOrigin(req);
      if (path === '/api/bootstrap' && method === 'GET') {
        const s = getSession(req), customer = s && db.prepare('SELECT * FROM customers WHERE id=?').get(s.customer_id);
        return json(res, { customer: publicCustomer(db,customer), csrf: s?.csrf, wechat: wxStatus(), warehouse: customer ? warehouse(customer.transfer_id) : null });
      }
      if (path === '/api/register' && method === 'POST') {
        rate(req,'register',10); const b = await body(req);
        const hash = await hashPassword(password(b.password));
        const customer = createCustomer(db, { ...profileInput(b), email: email(b.email,true), password_hash: hash });
        audit(null,customer.id,'客户邮箱注册');
        return json(res,{ customer: publicCustomer(db,customer), csrf: newSession(req,res,customer.id) },201);
      }
      if (path === '/api/login' && method === 'POST') {
        rate(req,'login'); const b = await body(req);
        const row = db.prepare('SELECT * FROM customers WHERE email=?').get(email(b.email,true));
        if (!await verifyPassword(b.password,row?.password_hash)) fail('邮箱或密码不正确',401);
        return json(res,{customer:publicCustomer(db,row),csrf:newSession(req,res,row.id)});
      }
      if (path === '/api/logout' && method === 'POST') {
        const s = requireSession(req); db.prepare('DELETE FROM sessions WHERE token_hash=?').run(s.token_hash); cookie(res,'bilin_customer','',0); return json(res,{ok:true});
      }
      if (path === '/api/profile' && method === 'PATCH') {
        const s = requireSession(req), b = await body(req), p = profileInput(b);
        db.prepare("UPDATE customers SET nickname=?,phone=?,country=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").run(p.nickname,p.phone,p.country,s.customer_id);
        audit(s,s.customer_id,'修改个人资料'); return json(res,{customer:publicCustomer(db,db.prepare('SELECT * FROM customers WHERE id=?').get(s.customer_id))});
      }
      if (path === '/api/account' && method === 'PATCH') {
        const s = requireSession(req); rate(req,'account'); const b = await body(req), row = db.prepare('SELECT * FROM customers WHERE id=?').get(s.customer_id);
        if (row.password_hash && !await verifyPassword(b.current_password,row.password_hash)) fail('当前密码不正确',403);
        if (!row.password_hash && s.authenticated_at < now()-15*60000) fail('请重新通过微信登录后设置邮箱与密码',403);
        const nextEmail = email(b.email,true), nextHash = b.new_password ? await hashPassword(password(b.new_password)) : row.password_hash;
        if (!nextHash) fail('首次绑定邮箱需要设置密码');
        transaction(db,()=> { db.prepare("UPDATE customers SET email=?,password_hash=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").run(nextEmail,nextHash,row.id); db.prepare('DELETE FROM sessions WHERE customer_id=?').run(row.id); });
        const csrf = newSession(req,res,row.id); audit(s,row.id,'修改邮箱或密码'); return json(res,{csrf,customer:publicCustomer(db,db.prepare('SELECT * FROM customers WHERE id=?').get(row.id))});
      }
      if (path === '/api/theme' && method === 'PATCH') {
        const s = requireSession(req), b = await body(req); if (!themeValues.includes(b.theme)) fail('请选择有效皮肤');
        db.prepare('UPDATE customers SET theme=? WHERE id=?').run(b.theme,s.customer_id); return json(res,{theme:b.theme});
      }
      if (path === '/api/addresses') {
        const s = requireSession(req);
        if (method === 'GET') return json(res,{addresses:db.prepare('SELECT * FROM addresses WHERE customer_id=? ORDER BY is_default DESC,id DESC').all(s.customer_id)});
        if (method === 'POST') { const row = saveAddress(s.customer_id,null,await body(req)); audit(s,s.customer_id,'新增收件地址'); return json(res,{address:row},201); }
      }
      const addr = path.match(/^\/api\/addresses\/(\d+)$/);
      if (addr) {
        const s = requireSession(req), id = Number(addr[1]);
        if (method === 'PATCH') { const row=saveAddress(s.customer_id,id,await body(req));audit(s,s.customer_id,'修改收件地址');return json(res,{address:row}); }
        if (method === 'DELETE') {
          transaction(db,()=>{const result=db.prepare('DELETE FROM addresses WHERE id=? AND customer_id=?').run(id,s.customer_id);if(!result.changes)fail('地址不存在',404);if(!db.prepare('SELECT id FROM addresses WHERE customer_id=? AND is_default=1').get(s.customer_id))db.prepare('UPDATE addresses SET is_default=1 WHERE id=(SELECT id FROM addresses WHERE customer_id=? ORDER BY id LIMIT 1)').run(s.customer_id);});
          audit(s,s.customer_id,'删除收件地址');return json(res,{ok:true});
        }
      }
      if (path === '/api/wechat/start' && method === 'GET') {
        rate(req,'wechat',30); const mode=url.searchParams.get('mode')==='mp'?'mp':'web', c=config();
        if (!wxStatus()[mode]) fail('微信登录尚未配置，请使用邮箱登录',503);
        const bind=url.searchParams.get('bind')==='1', s=bind?requireSession(req):null;
        if(bind && s.authenticated_at<now()-15*60000)fail('请重新登录后绑定微信',403);
        const state=token(), browser=token();
        db.prepare('DELETE FROM oauth_states WHERE expires_at<?').run(now());
        db.prepare('INSERT INTO oauth_states(token_hash,browser_hash,mode,customer_id,session_hash,expires_at) VALUES(?,?,?,?,?,?)').run(digest(state),digest(browser),mode,s?.customer_id||null,s?.token_hash||null,now()+10*60000);
        cookie(res,'bilin_oauth',browser,600);
        const target=new URL(mode==='mp'?'https://open.weixin.qq.com/connect/oauth2/authorize':'https://open.weixin.qq.com/connect/qrconnect');
        Object.entries({appid:c[mode==='mp'?'WECHAT_MP_APP_ID':'WECHAT_WEB_APP_ID'],redirect_uri:c.WECHAT_CALLBACK_URL,response_type:'code',scope:mode==='mp'?'snsapi_userinfo':'snsapi_login',state}).forEach(([k,v])=>target.searchParams.set(k,v));
        target.hash='wechat_redirect'; return redirect(res,target.toString());
      }
      if (path === '/api/wechat/callback' && method === 'GET') {
        try {
          const state=url.searchParams.get('state')||'', browser=cookies(req).bilin_oauth||'';
          const row=db.prepare('SELECT * FROM oauth_states WHERE token_hash=? AND browser_hash=? AND expires_at>?').get(digest(state),digest(browser),now());
          if(!row)fail('微信授权已过期，请重新发起登录',403);
          db.prepare('DELETE FROM oauth_states WHERE token_hash=?').run(row.token_hash);cookie(res,'bilin_oauth','',0);
          const code=text(url.searchParams.get('code'),'微信授权码',512,true), c=config(), appId=c[row.mode==='mp'?'WECHAT_MP_APP_ID':'WECHAT_WEB_APP_ID'];
          if(row.customer_id){const s=getSession(req);if(!s||s.token_hash!==row.session_hash||s.customer_id!==row.customer_id)fail('绑定会话已失效，请重新登录',403);}
          const access=await wechatGet('oauth2/access_token',{appid:appId,secret:c[row.mode==='mp'?'WECHAT_MP_APP_SECRET':'WECHAT_WEB_APP_SECRET'],code,grant_type:'authorization_code'});
          if(!access.openid||!access.access_token)fail('微信授权响应不完整',502);
          const info=await wechatGet('userinfo',{access_token:access.access_token,openid:access.openid,lang:'zh_CN'});
          const union=info.unionid||access.unionid||null;
          let customerId;
          // 客户创建和身份绑定在一个事务中，UnionID 只能在微信返回后使用。
          transaction(db,()=>{
            const identity=db.prepare('SELECT customer_id FROM wechat_identities WHERE app_id=? AND open_id=?').get(appId,access.openid);
            const byUnion=union?db.prepare('SELECT DISTINCT customer_id FROM wechat_identities WHERE union_id=?').all(union):[];
            if(byUnion.length>1)fail('微信关联存在冲突，请联系客服',409);
            const existing=identity?.customer_id||byUnion[0]?.customer_id;
            if(row.customer_id && existing && existing!==row.customer_id)fail('该微信已绑定其他账号',409);
            customerId=row.customer_id||existing;
            if(!customerId){const used=new Set(db.prepare('SELECT transfer_id FROM customers').all().map(r=>r.transfer_id));const free=[];for(let i=0;i<10000;i++){const id=String(i).padStart(4,'0');if(!used.has(id))free.push(id);}if(!free.length)fail('转运 ID 已全部分配',409);const {randomInt}=cryptoModule;customerId=Number(db.prepare('INSERT INTO customers(transfer_id,nickname) VALUES(?,?)').run(free[randomInt(free.length)],text(info.nickname||'微信客户','昵称',60)).lastInsertRowid);}
            if(!identity)db.prepare('INSERT INTO wechat_identities(customer_id,app_id,open_id,union_id) VALUES(?,?,?,?)').run(customerId,appId,access.openid,union);
            else if(union)db.prepare('UPDATE wechat_identities SET union_id=? WHERE app_id=? AND open_id=?').run(union,appId,access.openid);
          });
          newSession(req,res,customerId);audit({customer_id:customerId},customerId,row.customer_id?'绑定微信':'微信登录');return redirect(res,row.customer_id?'/#account':'/#home');
        }catch(error){return redirect(res,`/?auth_error=${encodeURIComponent(error.status?error.message:'微信服务暂时不可用，请重试')}#login`);}
      }
      if (path === '/api/admin/bootstrap' && method === 'GET') {
        const s=getSession(req,'staff'), row=s&&db.prepare('SELECT id,name,email,role FROM staff WHERE id=?').get(s.staff_id);
        return json(res,{staff:row||null,csrf:s?.csrf,setup_available:setupAllowed(req)});
      }
      if (path === '/api/admin/setup' && method === 'POST') {
        if(!setupAllowed(req))fail('初始化入口已关闭',403);rate(req,'setup',5);const b=await body(req), hash=await hashPassword(password(b.password));
        const id=transaction(db,()=>{if(db.prepare('SELECT id FROM staff LIMIT 1').get())fail('已完成初始化',409);return Number(db.prepare('INSERT INTO staff(email,password_hash,name) VALUES(?,?,?)').run(email(b.email,true),hash,text(b.name,'管理员姓名',60,true)).lastInsertRowid);});
        return json(res,{csrf:newSession(req,res,id,'staff'),staff:db.prepare('SELECT id,name,email,role FROM staff WHERE id=?').get(id)},201);
      }
      if (path === '/api/admin/login' && method === 'POST') {
        rate(req,'staff-login');const b=await body(req),row=db.prepare('SELECT * FROM staff WHERE email=?').get(email(b.email,true));
        if(!await verifyPassword(b.password,row?.password_hash))fail('邮箱或密码不正确',401);
        return json(res,{staff:{id:row.id,name:row.name,email:row.email,role:row.role},csrf:newSession(req,res,row.id,'staff')});
      }
      if(path.startsWith('/api/admin/')) {
        const s=requireSession(req,'staff');
        if(path==='/api/admin/logout'&&method==='POST'){db.prepare('DELETE FROM sessions WHERE token_hash=?').run(s.token_hash);cookie(res,'bilin_staff','',0);return json(res,{ok:true});}
        if(path==='/api/admin/customers'&&method==='GET'){
          const q=text(url.searchParams.get('q'),'搜索词',100),page=Math.max(1,Math.min(100000,Number(url.searchParams.get('page'))||1));
          const pattern=`%${q.replace(/[\\%_]/g,'\\$&')}%`,where="WHERE transfer_id LIKE ? ESCAPE '\\' OR nickname LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\'";
          const args=[pattern,pattern,pattern,pattern],total=db.prepare(`SELECT COUNT(*) total FROM customers ${where}`).get(...args).total;
          return json(res,{customers:db.prepare(`SELECT * FROM customers ${where} ORDER BY id DESC LIMIT 20 OFFSET ?`).all(...args,(page-1)*20).map(row=>publicCustomer(db,row)),total,page});
        }
        if(path==='/api/admin/customers'&&method==='POST'){
          const b=await body(req),mail=email(b.email),hash=b.password?await hashPassword(password(b.password)):null;
          if(mail&&!hash)fail('填写邮箱时，请设置初始密码');if(hash&&!mail)fail('设置密码时，请填写登录邮箱');
          const row=createCustomer(db,{...profileInput(b),email:mail,password_hash:hash,internal_note:text(b.internal_note,'内部备注',2000),created_by:s.staff_id});audit(s,row.id,'客服建立客户账号');return json(res,{customer:publicCustomer(db,row)},201);
        }
        const detail=path.match(/^\/api\/admin\/customers\/(\d+)$/);
        if(detail){const id=Number(detail[1]),row=db.prepare('SELECT * FROM customers WHERE id=?').get(id);if(!row)fail('客户不存在',404);
          if(method==='GET')return json(res,{customer:{...publicCustomer(db,row),internal_note:row.internal_note,created_by:row.created_by},warehouse:warehouse(row.transfer_id),addresses:db.prepare('SELECT * FROM addresses WHERE customer_id=? ORDER BY is_default DESC,id DESC').all(id),audit:db.prepare('SELECT action,detail,actor_type,actor_id,created_at FROM audit WHERE customer_id=? ORDER BY id DESC LIMIT 50').all(id)});
          if(method==='PATCH'){const b=await body(req),p=profileInput(b);db.prepare("UPDATE customers SET nickname=?,phone=?,country=?,internal_note=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").run(p.nickname,p.phone,p.country,text(b.internal_note,'内部备注',2000),id);audit(s,id,'后台修改客户资料与备注');return json(res,{ok:true});}
        }
        const adminAddr=path.match(/^\/api\/admin\/customers\/(\d+)\/addresses(?:\/(\d+))?$/);
        if(adminAddr){const id=Number(adminAddr[1]),aid=adminAddr[2]?Number(adminAddr[2]):null;if(!db.prepare('SELECT id FROM customers WHERE id=?').get(id))fail('客户不存在',404);if(method==='POST'&&!aid||method==='PATCH'&&aid){const a=saveAddress(id,aid,await body(req));audit(s,id,'后台维护收件地址');return json(res,{address:a});}}
        const reset=path.match(/^\/api\/admin\/customers\/(\d+)\/credentials$/);
        if(reset&&method==='PATCH'){
          const id=Number(reset[1]),b=await body(req),staff=db.prepare('SELECT * FROM staff WHERE id=?').get(s.staff_id);
          if(!await verifyPassword(b.staff_password,staff.password_hash))fail('请填写正确的后台登录密码',403);
          if(!db.prepare('SELECT id FROM customers WHERE id=?').get(id))fail('客户不存在',404);
          const hash=await hashPassword(password(b.password)),mail=email(b.email,true);
          transaction(db,()=>{db.prepare('UPDATE customers SET email=?,password_hash=? WHERE id=?').run(mail,hash,id);db.prepare('DELETE FROM sessions WHERE customer_id=?').run(id);});audit(s,id,'客服设置登录邮箱与重置密码');return json(res,{ok:true});
        }
        if(path==='/api/admin/wechat'){
          const staff=db.prepare('SELECT * FROM staff WHERE id=?').get(s.staff_id);if(staff.role!=='admin')fail('仅管理员可维护微信配置',403);
          const c=config();
          if(method==='GET')return json(res,{values:Object.fromEntries(wxKeys.filter(k=>!k.endsWith('SECRET')).map(k=>[k,c[k]])),secrets:{WECHAT_MP_APP_SECRET:Boolean(c.WECHAT_MP_APP_SECRET),WECHAT_WEB_APP_SECRET:Boolean(c.WECHAT_WEB_APP_SECRET)},status:wxStatus()});
          if(method==='PATCH'){
            const b=await body(req);if(!await verifyPassword(b.staff_password,staff.password_hash))fail('请填写正确的后台登录密码',403);
            const changes=[];for(const key of wxKeys){if(b[key]===undefined)continue;const value=text(b[key],key,1000);if(key.endsWith('SECRET')&&!value)continue;if(key==='WECHAT_CALLBACK_URL'&&value){let callback;try{callback=new URL(value);}catch{fail('回调地址格式不正确');}if(callback.origin!==new URL(appUrl).origin||callback.pathname!=='/api/wechat/callback'||callback.search||callback.hash)fail('回调地址必须为本站 /api/wechat/callback');if(!secure&&process.env.NODE_ENV==='production')fail('生产环境微信回调必须使用 HTTPS');}changes.push([key,value]);}
            transaction(db,()=>{for(const [k,v] of changes)db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k,v);});audit(s,null,'更新微信登录配置');return json(res,{ok:true,status:wxStatus()});
          }
        }
      }
      if(path.startsWith('/api/'))fail('接口不存在',404);
      if(!['GET','HEAD'].includes(method))fail('不支持此请求',405);
      const allowed=new Set(['/','/admin','/admin/','/app.js','/admin.js','/style.css','/common.js','/logo.svg']);
      if(!allowed.has(path))fail('页面不存在',404);
      const file=path.startsWith('/admin')?'admin.html':path==='/'?'index.html':path.slice(1);
      const data=await readFile(resolve(root,file)),type={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'}[extname(file)];
      res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-cache'});res.end(method==='HEAD'?undefined:data);
    }catch(error){if(res.headersSent){res.end();return;}let status=error.status||500,message=error.status?error.message:'服务暂时不可用，请稍后重试';if(error.code?.startsWith('ERR_SQLITE')&&error.message.includes('UNIQUE')){status=409;message='该邮箱或微信已被其他账号使用';}if(status===500)console.error('Request failed',req.method,req.url?.split('?')[0],error.code||error.name);json(res,{error:message},status);}
  });
  return {server,db};
}
import * as cryptoModule from 'node:crypto';
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const {server}=createApp();const port=Number(process.env.PORT||3000),host=process.env.HOST||'127.0.0.1';
  server.listen(port,host,()=>console.log(`比邻到门已启动：http://${host}:${port} | 后台：/admin`));
}
