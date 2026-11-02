
import { transformLuau, validateBasic } from './transform.js';

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
});
const now = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
async function sha256(value) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value)))); }
function safeEqual(a, b) {
  a = String(a ?? ''); b = String(b ?? '');
  let diff = a.length ^ b.length;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i % (a.length || 1)) || 0) ^ (b.charCodeAt(i % (b.length || 1)) || 0);
  return diff === 0;
}
function cookies(request) {
  const out = {};
  for (const item of (request.headers.get('cookie') || '').split(';')) {
    const i = item.indexOf('='); if (i > 0) { try { out[item.slice(0, i).trim()] = decodeURIComponent(item.slice(i + 1).trim()); } catch { /* Ignore malformed cookie values. */ } }
  }
  return out;
}
function cookie(value, maxAge) {
  return `sentinel_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
async function body(request) { try { return await request.json(); } catch { return {}; } }
function text(value, max = 200) { return String(value ?? '').trim().slice(0, max); }
function cleanFilename(value) { return text(value || 'main.luau', 100).replace(/[^a-zA-Z0-9._-]/g, '_') || 'main.luau'; }
function getIP(request) { return request.headers.get('CF-Connecting-IP') || 'unknown'; }
function corsOrigin(request) { return new URL(request.url).origin; }
function sameOrigin(request) {
  const origin = request.headers.get('Origin');
  return !origin || origin === corsOrigin(request);
}
async function audit(env, request, event, detail = '') {
  await env.DB.prepare('INSERT INTO audit(event,detail,ip_hash,created_at) VALUES(?,?,?,?)')
    .bind(text(event, 80), text(detail, 500), await sha256(getIP(request)), now()).run();
}
async function rateLimit(env, bucket, request, max, windowSeconds) {
  const subject = await sha256(getIP(request));
  const start = Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds;
  await env.DB.prepare(`INSERT INTO rate_limits(bucket,subject_hash,window_start,count) VALUES(?,?,?,1)
    ON CONFLICT(bucket,subject_hash,window_start) DO UPDATE SET count=count+1`)
    .bind(bucket, subject, start).run();
  const row = await env.DB.prepare('SELECT count FROM rate_limits WHERE bucket=? AND subject_hash=? AND window_start=?')
    .bind(bucket, subject, start).first();
  return (row?.count || 0) <= max;
}
async function getUser(request, env) {
  const token = cookies(request).sentinel_session;
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare('SELECT username,expires_at FROM sessions WHERE token_hash=?').bind(tokenHash).first();
  if (!row || row.expires_at <= Math.floor(Date.now() / 1000)) {
    if (row) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(tokenHash).run();
    return null;
  }
  return row.username;
}
async function requireAuth(request, env) {
  const username = await getUser(request, env);
  return username ? { username } : null;
}
async function admin(request, env, handler) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Sign in required.' }, 401);
  return handler(user);
}
function projectOut(r) { return { id:r.id, name:r.name, description:r.description, createdAt:r.created_at, updatedAt:r.updated_at }; }
function licenseOut(r) { return { id:r.id, prefix:r.key_prefix, label:r.label, scriptId:r.script_id, status:r.status, expiresAt:r.expires_at, maxActivations:r.max_activations, createdAt:r.created_at, revokedAt:r.revoked_at, lastSeenAt:r.last_seen_at }; }

async function routeAPI(request, env, ctx) {
  const url = new URL(request.url), path = url.pathname.replace(/\/$/, '') || '/', method = request.method;
  if (method === 'OPTIONS') return new Response(null, { status:204, headers:{'allow':'GET, POST, DELETE, OPTIONS'} });
  if (method !== 'GET' && !sameOrigin(request)) return json({ error:'Cross-origin request rejected.' }, 403);

  if (path === '/api/health' && method === 'GET') return json({ service: env.APP_NAME || 'Sentinel', version: env.APP_VERSION || '3.0.0', ok:true, runtime:'Cloudflare Workers', database:'D1', storage:'R2' });

  if (path === '/api/login' && method === 'POST') {
    if (!await rateLimit(env, 'login', request, 10, 900)) return json({ error:'Too many sign-in attempts. Try again later.' }, 429);
    const data = await body(request);
    const expectedUser = env.ADMIN_USERNAME || 'admin';
    const expectedPassword = env.ADMIN_PASSWORD;
    if (!expectedPassword) return json({ error:'Admin password secret is not configured.' }, 503);
    if (!safeEqual(text(data.username, 120), expectedUser) || !safeEqual(await sha256(String(data.password || '')), await sha256(expectedPassword))) {
      await audit(env, request, 'login_failed', text(data.username || 'unknown', 120));
      return json({ error:'Invalid username or password.' }, 401);
    }
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    const ttl = Math.max(900, Math.min(86400, Number(env.SESSION_TTL_SECONDS || 28800)));
    const expires = Math.floor(Date.now()/1000) + ttl;
    await env.DB.prepare('INSERT INTO sessions(token_hash,username,expires_at,created_at) VALUES(?,?,?,?)')
      .bind(await sha256(token), expectedUser, expires, now()).run();
    await audit(env, request, 'login_success', expectedUser);
    return json({ ok:true, username:expectedUser }, 200, { 'set-cookie':cookie(token, ttl) });
  }

  if (path === '/api/logout' && method === 'POST') {
    const token = cookies(request).sentinel_session;
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
    return json({ ok:true }, 200, { 'set-cookie':cookie('', 0) });
  }

  if (path === '/api/me' && method === 'GET') {
    const user = await requireAuth(request, env);
    return user ? json({ username:user.username }) : json({ error:'Sign in required.' }, 401);
  }

  if (path === '/api/license/validate' && method === 'POST') {
    if (!await rateLimit(env, 'license_validate', request, 90, 60)) return json({ valid:false, reason:'rate_limited' }, 429);
    const data = await body(request), key = text(data.key, 200), scriptId = text(data.scriptId || '*', 100), hwid = text(data.hwid, 300);
    if (!key || !hwid) return json({ valid:false, reason:'missing_key_or_hwid' }, 400);
    const keyHash = await sha256(key);
    const license = await env.DB.prepare('SELECT * FROM licenses WHERE key_hash=?').bind(keyHash).first();
    const timestamp = now();
    if (!license || license.status !== 'active' || (license.script_id !== '*' && license.script_id !== scriptId) || (license.expires_at && license.expires_at <= timestamp)) {
      await audit(env, request, 'license_validation_failed', license?.id || 'unknown');
      return json({ valid:false, reason:!license ? 'invalid_key' : license.status !== 'active' ? 'revoked' : (license.expires_at && license.expires_at <= timestamp) ? 'expired' : 'script_mismatch' });
    }
    const hwidHash = await sha256(hwid);
    let activation = await env.DB.prepare('SELECT id FROM license_activations WHERE license_id=? AND hwid_hash=?').bind(license.id, hwidHash).first();
    if (!activation) {
      const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM license_activations WHERE license_id=?').bind(license.id).first();
      if ((count?.n || 0) >= license.max_activations) return json({ valid:false, reason:'activation_limit_reached' });
      const inserted = await env.DB.prepare(`INSERT INTO license_activations(id,license_id,hwid_hash,created_at,last_seen_at)
        SELECT ?,?,?,?,? WHERE (SELECT COUNT(*) FROM license_activations WHERE license_id=?) < ?`)
        .bind(uuid(), license.id, hwidHash, timestamp, timestamp, license.id, license.max_activations).run();
      if (!inserted.meta?.changes) {
        activation = await env.DB.prepare('SELECT id FROM license_activations WHERE license_id=? AND hwid_hash=?').bind(license.id, hwidHash).first();
        if (!activation) return json({ valid:false, reason:'activation_limit_reached' });
      }
      if (activation) await env.DB.prepare('UPDATE license_activations SET last_seen_at=? WHERE id=?').bind(timestamp, activation.id).run();
    } else {
      await env.DB.prepare('UPDATE license_activations SET last_seen_at=? WHERE id=?').bind(timestamp, activation.id).run();
    }
    await env.DB.prepare('UPDATE licenses SET last_seen_at=? WHERE id=?').bind(timestamp, license.id).run();
    await audit(env, request, 'license_validation_success', license.id);
    return json({ valid:true, reason:'active', expiresAt:license.expires_at || null });
  }

  const protectedRoutes = ['/api/projects','/api/builds','/api/licenses','/api/audit','/api/settings','/api/stats'];
  if (protectedRoutes.some(p => path === p || path.startsWith(p + '/'))) {
    return admin(request, env, async () => {
      if (path === '/api/stats' && method === 'GET') {
        const [p,b,l,a,activations] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) AS n FROM projects').first(),
          env.DB.prepare('SELECT COUNT(*) AS n FROM builds').first(),
          env.DB.prepare("SELECT COUNT(*) AS n FROM licenses WHERE status='active' AND (expires_at IS NULL OR expires_at>?)").bind(now()).first(),
          env.DB.prepare('SELECT COUNT(*) AS n FROM audit WHERE created_at >= ?').bind(new Date(Date.now()-86400000).toISOString()).first(),
          env.DB.prepare('SELECT COUNT(*) AS n FROM license_activations').first()
        ]);
        return json({ projects:p?.n||0, builds:b?.n||0, activeLicenses:l?.n||0, auditLast24h:a?.n||0, activations:activations?.n||0 });
      }

      if (path === '/api/projects' && method === 'GET') {
        const { results=[] } = await env.DB.prepare('SELECT * FROM projects ORDER BY created_at DESC').all();
        return json(results.map(projectOut));
      }

      if (path === '/api/projects' && method === 'POST') {
        const data = await body(request), name = text(data.name, 100), description = text(data.description, 500);
        if (!name) return json({ error:'Project name is required.' }, 400);
        const id = uuid(), time = now();
        await env.DB.prepare('INSERT INTO projects(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)').bind(id,name,description,time,time).run();
        await audit(env, request, 'project_created', name);
        return json({ id,name,description,createdAt:time,updatedAt:time }, 201);
      }

      const projectMatch = path.match(/^\/api\/projects\/([^/]+)$/);
      if (projectMatch && method === 'GET') {
        const p = await env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(projectMatch[1]).first();
        if (!p) return json({ error:'Project not found.' }, 404);
        const { results=[] } = await env.DB.prepare('SELECT id,project_id,filename,source_hash,output_hash,source_bytes,output_bytes,created_at,status FROM builds WHERE project_id=? ORDER BY created_at DESC').bind(p.id).all();
        return json({ ...projectOut(p), builds:results });
      }

      if (projectMatch && method === 'PATCH') {
        const existing = await env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(projectMatch[1]).first();
        if (!existing) return json({ error:'Project not found.' }, 404);
        const data = await body(request), name = data.name === undefined ? existing.name : text(data.name,100), description = data.description === undefined ? existing.description : text(data.description,500);
        if (!name) return json({ error:'Project name is required.' },400);
        const time = now();
        await env.DB.prepare('UPDATE projects SET name=?,description=?,updated_at=? WHERE id=?').bind(name,description,time,existing.id).run();
        await audit(env,request,'project_updated',name);
        return json({ id:existing.id,name,description,createdAt:existing.created_at,updatedAt:time });
      }

      if (projectMatch && method === 'DELETE') {
        const p = await env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(projectMatch[1]).first();
        if (!p) return json({ error:'Project not found.' },404);
        const { results=[] } = await env.DB.prepare('SELECT output_key FROM builds WHERE project_id=?').bind(p.id).all();
        for (const b of results) if (env.BUILDS) await env.BUILDS.delete(b.output_key);
        await env.DB.prepare('DELETE FROM builds WHERE project_id=?').bind(p.id).run();
        await env.DB.prepare('DELETE FROM projects WHERE id=?').bind(p.id).run();

        await audit(env, request, 'project_deleted', p.name);
        return json({ ok:true });
      }

      const buildMatch = path.match(/^\/api\/projects\/([^/]+)\/build$/);
      if (buildMatch && method === 'POST') {
        const p = await env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(buildMatch[1]).first();
        if (!p) return json({ error:'Project not found.' }, 404);
        const data = await body(request), source = data.source;
        if (typeof source !== 'string' || !source.trim()) return json({ error:'Provide Luau source.' }, 400);
        const sourceBytes = new TextEncoder().encode(source).byteLength;
        const maxBytes = Math.max(1000, Math.min(5_000_000, Number(env.MAX_SOURCE_BYTES || 1_000_000)));
        if (sourceBytes > maxBytes) return json({ error:`Source exceeds ${maxBytes} byte limit.` }, 413);
        const validation = validateBasic(source);
        if (!validation.ok) return json({ error:'Basic validation failed.', validation }, 422);
        const output = transformLuau(source), outputBytes = new TextEncoder().encode(output).byteLength;
        const id = uuid(), filename = cleanFilename(data.name), sourceHash = await sha256(source), outputHash = await sha256(output), outputKey = `builds/${id}/${filename}`;
        if (!env.BUILDS) return json({ error:'R2 bucket binding BUILDS is missing.' }, 503);
        await env.BUILDS.put(outputKey, output, { httpMetadata:{ contentType:'text/plain; charset=utf-8' }, customMetadata:{ projectId:p.id, buildId:id, sourceHash, outputHash } });
        const time = now();
        await env.DB.prepare('INSERT INTO builds(id,project_id,filename,source_hash,output_hash,output_key,source_bytes,output_bytes,created_at,status,validation_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
          .bind(id,p.id,filename,sourceHash,outputHash,outputKey,sourceBytes,outputBytes,time,'completed',JSON.stringify(validation)).run();
        await audit(env, request, 'build_created', `${p.name}:${filename}:${id}`);
        return json({ id,projectId:p.id,filename,sourceHash,outputHash,created_at:time,status:'completed',outputBytes,validation,protectionNote:'Conservative minimization only; not strong obfuscation.' }, 201);
      }
      if (path === '/api/builds' && method === 'GET') {
        const { results=[] } = await env.DB.prepare('SELECT id,project_id,filename,source_hash,output_hash,source_bytes,output_bytes,created_at,status FROM builds ORDER BY created_at DESC LIMIT 100').all();
        return json(results);
      }

      const downloadMatch = path.match(/^\/api\/builds\/([^/]+)\/download$/);
      if (downloadMatch && method === 'GET') {
        const b = await env.DB.prepare('SELECT * FROM builds WHERE id=?').bind(downloadMatch[1]).first();
        if (!b) return json({ error:'Build not found.' }, 404);
        const object = await env.BUILDS.get(b.output_key);
        if (!object) return json({ error:'Build output is missing from storage.' }, 404);
        return new Response(object.body, { headers:{ 'content-type':'text/plain; charset=utf-8', 'content-disposition':`attachment; filename="${b.filename.replace(/"/g,'')}"`, 'cache-control':'no-store' } });
      }

      const buildDeleteMatch = path.match(/^\/api\/builds\/([^/]+)$/);
      if (buildDeleteMatch && method === 'DELETE') {
        const b = await env.DB.prepare('SELECT * FROM builds WHERE id=?').bind(buildDeleteMatch[1]).first();
        if (!b) return json({ error:'Build not found.' },404);
        if (env.BUILDS) await env.BUILDS.delete(b.output_key);
        await env.DB.prepare('DELETE FROM builds WHERE id=?').bind(b.id).run();
        await audit(env,request,'build_deleted',`${b.filename}:${b.id}`);
        return json({ ok:true });
      }

      if (path === '/api/licenses' && method === 'GET') {
        const { results=[] } = await env.DB.prepare('SELECT l.*, (SELECT COUNT(*) FROM license_activations a WHERE a.license_id=l.id) AS activation_count FROM licenses l ORDER BY l.created_at DESC LIMIT 500').all();
        return json(results.map(r => ({ ...licenseOut(r), activationCount:r.activation_count || 0 })));
      }

      if (path === '/api/licenses/bulk' && method === 'POST') {
        const data = await body(request), count = Math.max(1, Math.min(100, Math.floor(Number(data.count || 1))));
        const label = text(data.label || 'Bulk license',100), scriptId = text(data.scriptId || '*',100);
        const maxActivations = Math.max(1,Math.min(100,Math.floor(Number(data.maxActivations || 1))));
        let expiresAt = null;
        if (data.expiresAt) {
          const parsed = new Date(data.expiresAt);
          if (Number.isNaN(parsed.getTime()) || parsed <= new Date()) return json({error:'Expiry must be a valid future date.'},400);
          expiresAt = parsed.toISOString();
        }
        const created = [];
        for (let i=0;i<count;i++) {
          const raw = `SENTINEL-${hex(crypto.getRandomValues(new Uint8Array(18))).toUpperCase()}`, id=uuid(), createdAt=now();
          await env.DB.prepare('INSERT INTO licenses(id,key_hash,key_prefix,label,script_id,status,max_activations,expires_at,last_seen_at,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
            .bind(id,await sha256(raw),raw.slice(0,17),count===1?label:`${label} ${i+1}`,scriptId,'active',maxActivations,expiresAt,null,createdAt,null).run();
          created.push({id,key:raw,label:count===1?label:`${label} ${i+1}`,scriptId,maxActivations,expiresAt,createdAt});
        }
        await audit(env,request,'licenses_bulk_created',`${count} licenses for ${scriptId}`);
        return json({ count, licenses:created, warning:'Copy these keys now. Complete keys are never stored.' },201);
      }

      if (path === '/api/licenses' && method === 'POST') {
        const data = await body(request), label = text(data.label || 'Unnamed key', 100), scriptId = text(data.scriptId || '*', 100);
        const maxActivations = Math.max(1, Math.min(100, Number(data.maxActivations || 1)));
        let expiresAt = null;
        if (data.expiresAt) {
          const parsed = new Date(data.expiresAt);
          if (Number.isNaN(parsed.getTime()) || parsed <= new Date()) return json({ error:'Expiry must be a valid future date.' }, 400);
          expiresAt = parsed.toISOString();
        }
        const raw = `SENTINEL-${hex(crypto.getRandomValues(new Uint8Array(18))).toUpperCase()}`;
        const row = { id:uuid(), key_hash:await sha256(raw), key_prefix:raw.slice(0,17), label, script_id:scriptId, status:'active', max_activations:maxActivations, expires_at:expiresAt, created_at:now(), revoked_at:null, last_seen_at:null };
        await env.DB.prepare('INSERT INTO licenses(id,key_hash,key_prefix,label,script_id,status,max_activations,expires_at,last_seen_at,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
          .bind(row.id,row.key_hash,row.key_prefix,row.label,row.script_id,row.status,row.max_activations,row.expires_at,null,row.created_at,null).run();
        await audit(env, request, 'license_created', `${label}:${row.id}`);
        return json({ ...licenseOut(row), key:raw, warning:'Copy this key now. Only its hash is stored.' }, 201);
      }

      const activationListMatch = path.match(/^\/api\/licenses\/([^/]+)\/activations$/);
      if (activationListMatch && method === 'GET') {
        const license = await env.DB.prepare('SELECT id FROM licenses WHERE id=?').bind(activationListMatch[1]).first();
        if (!license) return json({error:'License not found.'},404);
        const {results=[]} = await env.DB.prepare('SELECT id,created_at,last_seen_at FROM license_activations WHERE license_id=? ORDER BY last_seen_at DESC').bind(license.id).all();
        return json(results);
      }

      const activationDeleteMatch = path.match(/^\/api\/licenses\/([^/]+)\/activations\/([^/]+)$/);
      if (activationDeleteMatch && method === 'DELETE') {
        const result = await env.DB.prepare('DELETE FROM license_activations WHERE id=? AND license_id=?').bind(activationDeleteMatch[2],activationDeleteMatch[1]).run();
        if (!result.meta?.changes) return json({error:'Activation not found.'},404);
        await audit(env,request,'license_device_removed',`${activationDeleteMatch[1]}:${activationDeleteMatch[2]}`);
        return json({ok:true});
      }

      const licensePatchMatch = path.match(/^\/api\/licenses\/([^/]+)$/);
      if (licensePatchMatch && method === 'PATCH') {
        const license = await env.DB.prepare('SELECT * FROM licenses WHERE id=?').bind(licensePatchMatch[1]).first();
        if (!license) return json({error:'License not found.'},404);
        const data = await body(request);
        const label = data.label === undefined ? license.label : text(data.label,100);
        const maxActivations = data.maxActivations === undefined ? license.max_activations : Math.max(1,Math.min(100,Math.floor(Number(data.maxActivations))));
        let expiresAt = license.expires_at;
        if (data.expiresAt !== undefined) {
          if (data.expiresAt === null || data.expiresAt === '') expiresAt=null;
          else {
            const parsed=new Date(data.expiresAt);
            if (Number.isNaN(parsed.getTime())) return json({error:'Invalid expiry date.'},400);
            expiresAt=parsed.toISOString();
          }
        }
        await env.DB.prepare('UPDATE licenses SET label=?,max_activations=?,expires_at=? WHERE id=?').bind(label,maxActivations,expiresAt,license.id).run();
        await audit(env,request,'license_updated',license.id);
        return json({ok:true});
      }

      const resetMatch = path.match(/^\/api\/licenses\/([^/]+)\/reset-activations$/);
      if (resetMatch && method === 'POST') {
        const row = await env.DB.prepare('SELECT id FROM licenses WHERE id=?').bind(resetMatch[1]).first();
        if (!row) return json({ error:'License not found.' }, 404);
        await env.DB.prepare('DELETE FROM license_activations WHERE license_id=?').bind(row.id).run();
        await audit(env, request, 'license_activations_reset', row.id);
        return json({ ok:true });
      }

      const revokeMatch = path.match(/^\/api\/licenses\/([^/]+)\/revoke$/);
      if (revokeMatch && method === 'POST') {
        const row = await env.DB.prepare('SELECT * FROM licenses WHERE id=?').bind(revokeMatch[1]).first();
        if (!row) return json({ error:'License not found.' }, 404);
        await env.DB.prepare("UPDATE licenses SET status='revoked',revoked_at=? WHERE id=?").bind(now(),row.id).run();
        await audit(env, request, 'license_revoked', row.id);
        return json({ ok:true });
      }

      if (path === '/api/audit' && method === 'GET') {
        const { results=[] } = await env.DB.prepare('SELECT id,event,detail,created_at FROM audit ORDER BY id DESC LIMIT 200').all();
        return json(results);
      }

      if (path === '/api/settings' && method === 'GET') {
        return json({ appName:env.APP_NAME || 'Sentinel', version:env.APP_VERSION || '3.0.0', runtime:'Cloudflare Workers', database:'D1', objectStorage:'R2', maxSourceBytes:Number(env.MAX_SOURCE_BYTES || 1000000) });
      }

      return json({ error:'Not found.' }, 404);
    });
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      let response;
      if (url.pathname.startsWith('/api/')) {
        response = await routeAPI(request, env, ctx);
        if (!response) response = json({ error:'Not found.' }, 404);
      } else {
        response = await env.ASSETS.fetch(request);
      }
      const headers = new Headers(response.headers);
      headers.set('x-content-type-options', 'nosniff');
      headers.set('referrer-policy', 'same-origin');
      headers.set('x-frame-options', 'DENY');
      headers.set('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
      headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
      if (url.pathname.startsWith('/api/')) headers.set('cache-control', 'no-store');
      return new Response(response.body, { status:response.status, statusText:response.statusText, headers });
    } catch (error) {
      console.error('Sentinel request failed:', error?.stack || error);
      return json({ error:'Internal server error.' }, 500);
    }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(Promise.all([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Math.floor(Date.now()/1000)).run(),
      env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(Math.floor(Date.now()/1000)-86400).run()
    ]));
  }
};
