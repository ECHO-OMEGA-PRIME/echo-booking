/**
 * Echo Booking v2.0.0 — AI-Powered Appointment Scheduling + Stripe Payments
 * Cloudflare Worker with Hono, D1, KV, service bindings
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env { DB: D1Database; CACHE: KVNamespace; ENGINE_RUNTIME: Fetcher; SHARED_BRAIN: Fetcher; EMAIL_SENDER: Fetcher; ECHO_API_KEY?: string; STRIPE_SECRET_KEY?: string; STRIPE_WEBHOOK_SECRET?: string; BOOKING_HMAC_KEY?: string; }
interface RLState { c: number; t: number }

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});
app.use('*', cors({ origin: ['https://echo-ept.com','https://www.echo-ept.com','https://echo-op.com','https://www.echo-op.com','http://localhost:3000','http://localhost:3001'], allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Echo-API-Key'] }));

const uid = () => crypto.randomUUID();
const sanitize = (s: string, max = 2000) => s?.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max) ?? '';
const sanitizeBody = (o: Record<string, unknown>) => { const r: Record<string, unknown> = {}; for (const [k, v] of Object.entries(o)) r[k] = typeof v === 'string' ? sanitize(v) : v; return r; };
const tid = (c: any) => c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '';
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } });

// CORS headers (auto-added by Evolution Engine)
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key',
};

async function sendEmail(env: Env, to: string, subject: string, html: string): Promise<void> {
  if (!env.EMAIL_SENDER || !to) return;
  try {
    await env.EMAIL_SENDER.fetch('https://email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to, subject, html, from_name: 'Echo Booking' }),
    });
  } catch (e) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', msg: 'Email send failed', to, error: String(e) }));
  }
}

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-booking', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

// Rate limiting
async function rateLimit(kv: KVNamespace, key: string, limit: number, windowSec = 60): Promise<boolean> {
  const rlKey = `rl:${key}`; const now = Date.now();
  const raw = await kv.get(rlKey);
  if (!raw) { await kv.put(rlKey, JSON.stringify({ c: 1, t: now }), { expirationTtl: windowSec * 2 }); return false; }
  const st: RLState = JSON.parse(raw);
  const elapsed = (now - st.t) / 1000;
  const decay = Math.max(0, st.c - (elapsed / windowSec) * limit);
  const count = decay + 1;
  await kv.put(rlKey, JSON.stringify({ c: count, t: now }), { expirationTtl: windowSec * 2 });
  return count > limit;
}

app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status') return next();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const isWrite = ['POST','PUT','PATCH','DELETE'].includes(c.req.method);
  if (await rateLimit(c.env.CACHE, `${ip}:${isWrite ? 'w' : 'r'}`, isWrite ? 60 : 200)) return json({ error: 'Rate limited' }, 429);
  return next();
});

// Auth middleware — require API key for write operations
app.use('*', async (c, next) => {
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path.startsWith('/public/') || path.startsWith('/webhooks/')) return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

app.get('/', (c) => c.json({ service: 'echo-booking', version: '2.0.0', status: 'operational' }));
app.get('/health', (c) => json({ status: 'ok', service: 'echo-booking', version: '2.0.0', time: new Date().toISOString(), stripe: !!c.env.STRIPE_SECRET_KEY, payments: !!c.env.STRIPE_SECRET_KEY }));

// ═══════════════ TENANTS ═══════════════
app.post('/tenants', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO tenants (id,name,email,phone,timezone,currency,booking_window_days,min_notice_hours,cancellation_hours,buffer_minutes,max_daily_bookings,allow_waitlist,require_approval,confirmation_message,cancellation_policy) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, b.name, b.email||null, b.phone||null, b.timezone||'America/Chicago', b.currency||'USD', b.booking_window_days||60, b.min_notice_hours||1, b.cancellation_hours||24, b.buffer_minutes||0, b.max_daily_bookings||0, b.allow_waitlist??1, b.require_approval||0, b.confirmation_message||null, b.cancellation_policy||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /tenants', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.get('/tenants/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(r) : json({ error: 'Not found' }, 404);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /tenants/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.put('/tenants/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare('UPDATE tenants SET name=coalesce(?,name),email=coalesce(?,email),phone=coalesce(?,phone),timezone=coalesce(?,timezone),booking_window_days=coalesce(?,booking_window_days),min_notice_hours=coalesce(?,min_notice_hours),cancellation_hours=coalesce(?,cancellation_hours),buffer_minutes=coalesce(?,buffer_minutes),max_daily_bookings=coalesce(?,max_daily_bookings),allow_waitlist=coalesce(?,allow_waitlist),require_approval=coalesce(?,require_approval),updated_at=datetime(\'now\') WHERE id=?')
      .bind(b.name||null, b.email||null, b.phone||null, b.timezone||null, b.booking_window_days??null, b.min_notice_hours??null, b.cancellation_hours??null, b.buffer_minutes??null, b.max_daily_bookings??null, b.allow_waitlist??null, b.require_approval??null, c.req.param('id')).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'PUT /tenants/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ LOCATIONS ═══════════════
app.get('/locations', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM locations WHERE tenant_id=? AND is_active=1 ORDER BY name').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /locations', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/locations', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO locations (id,tenant_id,name,address,city,state,zip,phone,timezone) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.name, b.address||null, b.city||null, b.state||null, b.zip||null, b.phone||null, b.timezone||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /locations', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ SERVICES ═══════════════
app.get('/services', async (c) => {
  try {
    const t = tid(c); const cat = c.req.query('category');
    let q = 'SELECT * FROM services WHERE tenant_id=? AND is_active=1'; const p: string[] = [t];
    if (cat) { q += ' AND category=?'; p.push(cat); }
    q += ' ORDER BY sort_order, name';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /services', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/services', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO services (id,tenant_id,name,description,duration_minutes,price,currency,color,category,buffer_before,buffer_after,max_attendees,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.name, b.description||null, b.duration_minutes||60, b.price||0, b.currency||'USD', b.color||'#14b8a6', b.category||null, b.buffer_before||0, b.buffer_after||0, b.max_attendees||1, b.sort_order||0).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /services', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.put('/services/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare('UPDATE services SET name=coalesce(?,name),description=coalesce(?,description),duration_minutes=coalesce(?,duration_minutes),price=coalesce(?,price),color=coalesce(?,color),category=coalesce(?,category),buffer_before=coalesce(?,buffer_before),buffer_after=coalesce(?,buffer_after),max_attendees=coalesce(?,max_attendees),is_active=coalesce(?,is_active) WHERE id=? AND tenant_id=?')
      .bind(b.name||null, b.description||null, b.duration_minutes??null, b.price??null, b.color||null, b.category||null, b.buffer_before??null, b.buffer_after??null, b.max_attendees??null, b.is_active??null, c.req.param('id'), tid(c)).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'PUT /services/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ STAFF ═══════════════
app.get('/staff', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM staff WHERE tenant_id=? AND is_active=1 ORDER BY name').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /staff', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/staff', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO staff (id,tenant_id,name,email,phone,role,avatar_url,bio) VALUES (?,?,?,?,?,?,?,?)')
      .bind(id, t, b.name, b.email||null, b.phone||null, b.role||'staff', b.avatar_url||null, b.bio||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /staff', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.get('/staff/:id', async (c) => {
  try {
    const staff = await c.env.DB.prepare('SELECT * FROM staff WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    if (!staff) return json({ error: 'Not found' }, 404);
    const svcs = await c.env.DB.prepare('SELECT s.* FROM services s JOIN staff_services ss ON s.id=ss.service_id WHERE ss.staff_id=? AND ss.tenant_id=?').bind(c.req.param('id'), tid(c)).all();
    const avail = await c.env.DB.prepare('SELECT * FROM availability WHERE staff_id=? AND tenant_id=? AND is_active=1 ORDER BY day_of_week, start_time').bind(c.req.param('id'), tid(c)).all();
    const reviews = await c.env.DB.prepare('SELECT AVG(rating) as avg_rating, COUNT(*) as review_count FROM reviews WHERE staff_id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    return json({ ...staff, services: svcs.results, availability: avail.results, avg_rating: (reviews as any)?.avg_rating, review_count: (reviews as any)?.review_count });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /staff/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
// Assign services to staff
app.post('/staff/:id/services', async (c) => {
  try {
    const t = tid(c); const b = await c.req.json() as { service_ids: string[] };
    await c.env.DB.prepare('DELETE FROM staff_services WHERE staff_id=? AND tenant_id=?').bind(c.req.param('id'), t).run();
    for (const svcId of b.service_ids) {
      await c.env.DB.prepare('INSERT INTO staff_services (staff_id,service_id,tenant_id) VALUES (?,?,?)').bind(c.req.param('id'), svcId, t).run();
    }
    return json({ assigned: b.service_ids.length });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /staff/:id/services', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ AVAILABILITY ═══════════════
app.get('/availability', async (c) => {
  try {
    const t = tid(c); const staffId = c.req.query('staff_id');
    let q = 'SELECT a.*, s.name as staff_name FROM availability a LEFT JOIN staff s ON a.staff_id=s.id WHERE a.tenant_id=? AND a.is_active=1';
    const p: string[] = [t];
    if (staffId) { q += ' AND a.staff_id=?'; p.push(staffId); }
    q += ' ORDER BY a.day_of_week, a.start_time';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /availability', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/availability', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO availability (id,tenant_id,staff_id,day_of_week,start_time,end_time,location_id) VALUES (?,?,?,?,?,?,?)')
      .bind(id, t, b.staff_id, b.day_of_week, b.start_time, b.end_time, b.location_id||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /availability', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.delete('/availability/:id', async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM availability WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
    return json({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'DELETE /availability/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ TIME OFF ═══════════════
app.get('/time-off', async (c) => {
  try {
    const t = tid(c); const staffId = c.req.query('staff_id');
    let q = 'SELECT t.*, s.name as staff_name FROM time_off t LEFT JOIN staff s ON t.staff_id=s.id WHERE t.tenant_id=?'; const p: string[] = [t];
    if (staffId) { q += ' AND t.staff_id=?'; p.push(staffId); }
    q += ' ORDER BY t.start_date DESC';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /time-off', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/time-off', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO time_off (id,tenant_id,staff_id,start_date,end_date,reason) VALUES (?,?,?,?,?,?)')
      .bind(id, t, b.staff_id, b.start_date, b.end_date, b.reason||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /time-off', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ CUSTOMERS ═══════════════
app.get('/customers', async (c) => {
  try {
    const t = tid(c); const search = c.req.query('search');
    let q = 'SELECT * FROM customers WHERE tenant_id=?'; const p: string[] = [t];
    if (search) { q += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'; const s = `%${sanitize(search,100)}%`; p.push(s,s,s); }
    q += ' ORDER BY name LIMIT 200';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /customers', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/customers', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO customers (id,tenant_id,name,email,phone,notes) VALUES (?,?,?,?,?,?)')
      .bind(id, t, b.name, b.email||null, b.phone||null, b.notes||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /customers', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.get('/customers/:id', async (c) => {
  try {
    const t = tid(c); const cust = await c.env.DB.prepare('SELECT * FROM customers WHERE id=? AND tenant_id=?').bind(c.req.param('id'), t).first();
    if (!cust) return json({ error: 'Not found' }, 404);
    const appts = await c.env.DB.prepare('SELECT a.*, s.name as service_name, st.name as staff_name FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id WHERE a.customer_id=? AND a.tenant_id=? ORDER BY a.date DESC LIMIT 20').bind(c.req.param('id'), t).all();
    return json({ ...cust, appointments: appts.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /customers/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ APPOINTMENTS ═══════════════
// Get available slots for a service + staff on a date
app.get('/slots', async (c) => {
  try {
    const t = tid(c); const date = c.req.query('date'); const serviceId = c.req.query('service_id'); const staffId = c.req.query('staff_id');
    if (!date || !serviceId) return json({ error: 'date and service_id required' }, 400);
    const service = await c.env.DB.prepare('SELECT * FROM services WHERE id=? AND tenant_id=?').bind(serviceId, t).first() as any;
    if (!service) return json({ error: 'Service not found' }, 404);
    const dayOfWeek = new Date(date + 'T12:00:00Z').getUTCDay();
    // Get availability for staff (or all staff for this service)
    let availQ = 'SELECT a.* FROM availability a';
    const availP: string[] = [t];
    if (staffId) { availQ += ' WHERE a.tenant_id=? AND a.staff_id=? AND a.day_of_week=? AND a.is_active=1'; availP.push(staffId, String(dayOfWeek)); }
    else { availQ += ' JOIN staff_services ss ON a.staff_id=ss.staff_id WHERE a.tenant_id=? AND ss.service_id=? AND a.day_of_week=? AND a.is_active=1'; availP.push(serviceId, String(dayOfWeek)); }
    const avail = await c.env.DB.prepare(availQ).bind(...availP).all();
    // Get existing appointments
    const existing = await c.env.DB.prepare("SELECT * FROM appointments WHERE tenant_id=? AND date=? AND status NOT IN ('cancelled','no_show')").bind(t, date).all();
    // Check time off
    const timeOff = await c.env.DB.prepare("SELECT staff_id FROM time_off WHERE tenant_id=? AND start_date<=? AND end_date>=?").bind(t, date, date).all();
    const offStaff = new Set((timeOff.results as any[]).map(r => r.staff_id));
    // Generate slots
    const slots: { staff_id: string; start: string; end: string }[] = [];
    const duration = service.duration_minutes + (service.buffer_before || 0) + (service.buffer_after || 0);
    for (const a of avail.results as any[]) {
      if (offStaff.has(a.staff_id)) continue;
      const [sh, sm] = a.start_time.split(':').map(Number);
      const [eh, em] = a.end_time.split(':').map(Number);
      const startMin = sh * 60 + sm; const endMin = eh * 60 + em;
      for (let m = startMin; m + duration <= endMin; m += 15) {
        const slotStart = `${String(Math.floor(m/60)).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;
        const slotEnd = `${String(Math.floor((m+service.duration_minutes)/60)).padStart(2,'0')}:${String((m+service.duration_minutes)%60).padStart(2,'0')}`;
        // Check conflicts
        const conflict = (existing.results as any[]).some(e => e.staff_id === a.staff_id && timesOverlap(e.start_time, e.end_time, slotStart, slotEnd));
        if (!conflict) slots.push({ staff_id: a.staff_id, start: slotStart, end: slotEnd });
      }
    }
    return json({ date, service: service.name, duration_minutes: service.duration_minutes, slots });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /slots', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/appointments', async (c) => {
  try {
    const t = tid(c); const date = c.req.query('date'); const from = c.req.query('from'); const to = c.req.query('to');
    const staffId = c.req.query('staff_id'); const status = c.req.query('status');
    let q = 'SELECT a.*, s.name as service_name, st.name as staff_name, cu.name as customer_name, cu.email as customer_email, cu.phone as customer_phone FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.tenant_id=?';
    const p: string[] = [t];
    if (date) { q += ' AND a.date=?'; p.push(date); }
    if (from) { q += ' AND a.date>=?'; p.push(from); }
    if (to) { q += ' AND a.date<=?'; p.push(to); }
    if (staffId) { q += ' AND a.staff_id=?'; p.push(staffId); }
    if (status) { q += ' AND a.status=?'; p.push(status); }
    q += ' ORDER BY a.date, a.start_time LIMIT 500';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /appointments', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/appointments', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    // Get service for duration
    const svc = await c.env.DB.prepare('SELECT * FROM services WHERE id=? AND tenant_id=?').bind(b.service_id, t).first() as any;
    const endTime = (b.end_time as string) || addMinutes(b.start_time as string, svc?.duration_minutes || 60);
    // Max daily bookings enforcement
    const tenant = await c.env.DB.prepare("SELECT max_daily_bookings FROM tenants WHERE id = ?").bind(t).first();
    if (tenant?.max_daily_bookings) {
      const dayCount = await c.env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id = ? AND date = ? AND status NOT IN ('cancelled','no-show')"
      ).bind(t, b.date).first();
      if ((dayCount as any)?.cnt >= tenant.max_daily_bookings) return c.json({ error: 'Daily booking limit reached' }, 429);
    }
    const status = b.status || 'confirmed';
    // Atomic double-booking protection: INSERT only if no overlapping appointment exists
    const insertResult = await c.env.DB.prepare(
      `INSERT INTO appointments (id,tenant_id,customer_id,staff_id,service_id,location_id,status,start_time,end_time,date,price,notes,customer_notes,internal_notes,source)
       SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
       WHERE NOT EXISTS (
         SELECT 1 FROM appointments WHERE staff_id = ? AND date = ? AND status NOT IN ('cancelled','no-show')
         AND start_time < ? AND end_time > ?
       )`
    ).bind(id, t, b.customer_id, b.staff_id, b.service_id, b.location_id||null, status, b.start_time, endTime, b.date, b.price||svc?.price||0, b.notes||null, b.customer_notes||null, b.internal_notes||null, b.source||'manual',
      b.staff_id, b.date, endTime, b.start_time).run();
    if (!insertResult.meta.changes) return c.json({ error: 'Time slot already booked' }, 409);
    // Update customer stats
    await c.env.DB.prepare('UPDATE customers SET total_bookings=total_bookings+1,updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(b.customer_id, t).run();
    await logAct(c.env.DB, t, 'appointment', id, 'booked', `Appointment booked for ${b.date} ${b.start_time}`);
    // Send confirmation email (fire-and-forget)
    const customer = await c.env.DB.prepare('SELECT name, email FROM customers WHERE id=? AND tenant_id=?').bind(b.customer_id, t).first<{name:string;email:string}>();
    if (customer?.email) {
      sendEmail(c.env, customer.email, `Booking Confirmed — ${b.date}`,
        `<h2>Booking Confirmed</h2><p>Hi ${sanitize(customer.name || 'there', 50)},</p><p>Your appointment is confirmed:</p><ul><li><strong>Date:</strong> ${sanitize(String(b.date),20)}</li><li><strong>Time:</strong> ${sanitize(String(b.start_time),10)} — ${sanitize(endTime,10)}</li><li><strong>Service:</strong> ${sanitize(svc?.name || 'Appointment',100)}</li></ul><p>Thank you for booking with us!</p>`
      );
    }
    return json({ id, end_time: endTime }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /appointments', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/appointments/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT a.*, s.name as service_name, s.duration_minutes, st.name as staff_name, cu.name as customer_name, cu.email as customer_email, cu.phone as customer_phone FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.id=? AND a.tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    return r ? json(r) : json({ error: 'Not found' }, 404);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /appointments/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Cancel appointment
app.post('/appointments/:id/cancel', async (c) => {
  try {
    const t = tid(c); const b = await c.req.json() as { reason?: string };
    await c.env.DB.prepare("UPDATE appointments SET status='cancelled',cancellation_reason=?,cancelled_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?")
      .bind(b.reason||null, c.req.param('id'), t).run();
    // Check waitlist
    const appt = await c.env.DB.prepare('SELECT * FROM appointments WHERE id=?').bind(c.req.param('id')).first() as any;
    if (appt) {
      const waiters = await c.env.DB.prepare("SELECT * FROM waitlist WHERE tenant_id=? AND service_id=? AND status='waiting' AND (preferred_date IS NULL OR preferred_date=?) ORDER BY created_at LIMIT 3").bind(t, appt.service_id, appt.date).all();
      if (waiters.results.length > 0) {
        for (const w of waiters.results as any[]) {
          await c.env.DB.prepare("UPDATE waitlist SET status='notified',notified_at=datetime('now') WHERE id=?").bind(w.id).run();
          // Send waitlist notification email
          const wCustomer = await c.env.DB.prepare('SELECT name, email FROM customers WHERE id=?').bind(w.customer_id).first<{name:string;email:string}>();
          const wService = await c.env.DB.prepare('SELECT name FROM services WHERE id=?').bind(w.service_id).first<{name:string}>();
          if (wCustomer?.email) {
            sendEmail(c.env, wCustomer.email, `A Slot Just Opened Up!`,
              `<h2>Good News!</h2><p>Hi ${sanitize(wCustomer.name || 'there', 50)},</p><p>A time slot has opened up for <strong>${sanitize(wService?.name || 'your requested service',100)}</strong> on <strong>${sanitize(String(appt.date),20)}</strong>.</p><p>Book now before it fills up!</p>`
            );
          }
        }
      }
    }
    await logAct(c.env.DB, t, 'appointment', c.req.param('id'), 'cancelled', b.reason||'Cancelled');
    return json({ cancelled: true, waitlist_notified: appt ? true : false });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /appointments/:id/cancel', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Complete appointment
app.post('/appointments/:id/complete', async (c) => {
  try {
    const t = tid(c);
    await c.env.DB.prepare("UPDATE appointments SET status='completed',completed_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), t).run();
    const appt = await c.env.DB.prepare('SELECT * FROM appointments WHERE id=?').bind(c.req.param('id')).first() as any;
    if (appt) {
      await c.env.DB.prepare('UPDATE customers SET total_spent=total_spent+?,last_visit_at=datetime(\'now\'),updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(appt.price||0, appt.customer_id, t).run();
    }
    return json({ completed: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /appointments/:id/complete', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Mark no-show
app.post('/appointments/:id/no-show', async (c) => {
  try {
    const t = tid(c);
    await c.env.DB.prepare("UPDATE appointments SET status='no_show',no_show_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), t).run();
    const appt = await c.env.DB.prepare('SELECT customer_id FROM appointments WHERE id=?').bind(c.req.param('id')).first() as any;
    if (appt) {
      await c.env.DB.prepare('UPDATE customers SET no_show_count=no_show_count+1,updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(appt.customer_id, t).run();
    }
    return json({ marked: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /appointments/:id/no-show', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Reschedule
app.post('/appointments/:id/reschedule', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json());
    const svc = await c.env.DB.prepare('SELECT s.duration_minutes FROM appointments a JOIN services s ON a.service_id=s.id WHERE a.id=? AND a.tenant_id=?').bind(c.req.param('id'), t).first() as any;
    const endTime = (b.end_time as string) || addMinutes(b.start_time as string, svc?.duration_minutes||60);
    await c.env.DB.prepare("UPDATE appointments SET date=?,start_time=?,end_time=?,staff_id=coalesce(?,staff_id),status='confirmed',updated_at=datetime('now') WHERE id=? AND tenant_id=?")
      .bind(b.date, b.start_time, endTime, b.staff_id||null, c.req.param('id'), t).run();
    await logAct(c.env.DB, t, 'appointment', c.req.param('id'), 'rescheduled', `Rescheduled to ${b.date} ${b.start_time}`);
    return json({ rescheduled: true, end_time: endTime });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /appointments/:id/reschedule', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ STRIPE PAYMENTS ═══════════════

// HMAC-SHA256 helpers
async function hmacSign(key: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacVerify(key: string, data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(key, data);
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return result === 0;
}

function generateBookingToken(hmacKey: string, appointmentId: string): Promise<string> {
  return hmacSign(hmacKey, `booking:${appointmentId}`);
}

// POST /appointments/:id/checkout — Create Stripe Checkout session
app.post('/appointments/:id/checkout', async (c) => {
  try {
    if (!c.env.STRIPE_SECRET_KEY) return json({ error: 'Stripe not configured' }, 503);
    const t = tid(c); const apptId = c.req.param('id');
    const appt = await c.env.DB.prepare(
      'SELECT a.*, s.name as service_name, cu.name as customer_name, cu.email as customer_email FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.id=? AND a.tenant_id=?'
    ).bind(apptId, t).first<any>();
    if (!appt) return json({ error: 'Appointment not found' }, 404);
    if (appt.payment_status === 'paid') return json({ error: 'Already paid' }, 400);
    const amount = Math.round((appt.price || 0) * 100);
    if (amount <= 0) return json({ error: 'No amount to charge' }, 400);

    const body = await c.req.json().catch(() => ({})) as { success_url?: string; cancel_url?: string };
    const successUrl = body.success_url || `https://echo-booking.bmcii1976.workers.dev/public/booking/${apptId}/success`;
    const cancelUrl = body.cancel_url || `https://echo-booking.bmcii1976.workers.dev/public/booking/${apptId}/cancel`;

    const params = new URLSearchParams();
    params.append('mode', 'payment');
    params.append('payment_method_types[0]', 'card');
    params.append('line_items[0][price_data][currency]', (appt.currency || 'usd').toLowerCase());
    params.append('line_items[0][price_data][unit_amount]', String(amount));
    params.append('line_items[0][price_data][product_data][name]', appt.service_name || 'Appointment');
    params.append('line_items[0][price_data][product_data][description]', `Booking on ${appt.date} at ${appt.start_time}`);
    params.append('line_items[0][quantity]', '1');
    params.append('success_url', successUrl);
    params.append('cancel_url', cancelUrl);
    params.append('client_reference_id', apptId);
    if (appt.customer_email) params.append('customer_email', appt.customer_email);
    params.append('metadata[appointment_id]', apptId);
    params.append('metadata[tenant_id]', t);

    const stripeResp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
    const session = await stripeResp.json() as any;
    if (!stripeResp.ok) {
      slog('error', 'Stripe checkout creation failed', { status: stripeResp.status, error: session.error?.message });
      return json({ error: 'Stripe error', detail: session.error?.message }, 502);
    }

    await c.env.DB.prepare("UPDATE appointments SET stripe_checkout_id=?, payment_status='pending', updated_at=datetime('now') WHERE id=?")
      .bind(session.id, apptId).run();
    await logAct(c.env.DB, t, 'appointment', apptId, 'checkout_created', `Stripe checkout ${session.id}`);
    slog('info', 'Stripe checkout created', { appointment_id: apptId, session_id: session.id, amount });

    return json({ checkout_url: session.url, session_id: session.id });
  } catch (e: any) {
    slog('error', 'Checkout endpoint failed', { error: e?.message });
    return json({ error: 'Internal error' }, 500);
  }
});

// POST /appointments/:id/payment-link — Generate shareable payment link with HMAC token
app.post('/appointments/:id/payment-link', async (c) => {
  try {
    if (!c.env.BOOKING_HMAC_KEY) return json({ error: 'HMAC key not configured' }, 503);
    const t = tid(c); const apptId = c.req.param('id');
    const appt = await c.env.DB.prepare('SELECT id, price, payment_status FROM appointments WHERE id=? AND tenant_id=?').bind(apptId, t).first<any>();
    if (!appt) return json({ error: 'Appointment not found' }, 404);
    if (appt.payment_status === 'paid') return json({ error: 'Already paid' }, 400);
    const amount = Math.round((appt.price || 0) * 100);
    if (amount <= 0) return json({ error: 'No amount to charge' }, 400);

    const token = await generateBookingToken(c.env.BOOKING_HMAC_KEY, apptId);
    const link = `https://echo-booking.bmcii1976.workers.dev/public/booking/${apptId}?token=${token}`;
    slog('info', 'Payment link generated', { appointment_id: apptId });
    return json({ payment_link: link, token });
  } catch (e: any) {
    slog('error', 'Payment link generation failed', { error: e?.message });
    return json({ error: 'Internal error' }, 500);
  }
});

// GET /public/booking/:id — Public appointment confirmation page (HMAC token required)
app.get('/public/booking/:id', async (c) => {
  try {
    const apptId = c.req.param('id');
    const token = c.req.query('token');
    if (!token || !c.env.BOOKING_HMAC_KEY) return json({ error: 'Invalid or missing token' }, 403);

    const valid = await hmacVerify(c.env.BOOKING_HMAC_KEY, `booking:${apptId}`, token);
    if (!valid) return json({ error: 'Invalid token' }, 403);

    const appt = await c.env.DB.prepare(
      'SELECT a.id, a.date, a.start_time, a.end_time, a.price, a.status, a.payment_status, a.stripe_checkout_id, s.name as service_name, s.currency, st.name as staff_name, cu.name as customer_name FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.id=?'
    ).bind(apptId).first<any>();
    if (!appt) return json({ error: 'Appointment not found' }, 404);

    const amount = ((appt.price || 0)).toFixed(2);
    const isPaid = appt.payment_status === 'paid';
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Booking Confirmation</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f8fafc;color:#1e293b;display:flex;justify-content:center;padding:2rem}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,0.08);max-width:480px;width:100%;padding:2rem}
h1{font-size:1.5rem;margin-bottom:1rem;color:#0f172a}.row{display:flex;justify-content:space-between;padding:.75rem 0;border-bottom:1px solid #e2e8f0}
.label{color:#64748b;font-size:.875rem}.value{font-weight:600}
.price{font-size:1.75rem;color:#059669;text-align:center;margin:1.5rem 0}
.btn{display:block;width:100%;padding:1rem;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-top:1rem}
.btn:hover{background:#4f46e5}.paid{background:#059669;padding:1rem;border-radius:8px;color:#fff;text-align:center;font-weight:600;margin-top:1rem}
</style></head><body><div class="card">
<h1>Booking Confirmation</h1>
<div class="row"><span class="label">Service</span><span class="value">${appt.service_name || 'Appointment'}</span></div>
<div class="row"><span class="label">Date</span><span class="value">${appt.date}</span></div>
<div class="row"><span class="label">Time</span><span class="value">${appt.start_time} — ${appt.end_time}</span></div>
${appt.staff_name ? `<div class="row"><span class="label">With</span><span class="value">${appt.staff_name}</span></div>` : ''}
<div class="row"><span class="label">Status</span><span class="value">${appt.status}</span></div>
<div class="price">$${amount} ${(appt.currency || 'USD').toUpperCase()}</div>
${isPaid ? '<div class="paid">Payment Complete</div>' : `<a class="btn" href="/public/booking/${apptId}/pay?token=${token}">Pay Now</a>`}
</div></body></html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  } catch (e: any) {
    slog('error', 'Public booking page failed', { error: e?.message });
    return json({ error: 'Internal error' }, 500);
  }
});

// GET /public/booking/:id/pay — Redirect to Stripe Checkout (creates session if needed)
app.get('/public/booking/:id/pay', async (c) => {
  try {
    const apptId = c.req.param('id');
    const token = c.req.query('token');
    if (!token || !c.env.BOOKING_HMAC_KEY || !c.env.STRIPE_SECRET_KEY) return json({ error: 'Invalid or missing token' }, 403);

    const valid = await hmacVerify(c.env.BOOKING_HMAC_KEY, `booking:${apptId}`, token);
    if (!valid) return json({ error: 'Invalid token' }, 403);

    const appt = await c.env.DB.prepare(
      'SELECT a.*, s.name as service_name, s.currency, cu.email as customer_email FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.id=?'
    ).bind(apptId).first<any>();
    if (!appt) return json({ error: 'Appointment not found' }, 404);
    if (appt.payment_status === 'paid') return Response.redirect(`https://echo-booking.bmcii1976.workers.dev/public/booking/${apptId}?token=${token}`, 302);

    const amount = Math.round((appt.price || 0) * 100);
    if (amount <= 0) return json({ error: 'No amount to charge' }, 400);

    const baseUrl = 'https://echo-booking.bmcii1976.workers.dev';
    const params = new URLSearchParams();
    params.append('mode', 'payment');
    params.append('payment_method_types[0]', 'card');
    params.append('line_items[0][price_data][currency]', (appt.currency || 'usd').toLowerCase());
    params.append('line_items[0][price_data][unit_amount]', String(amount));
    params.append('line_items[0][price_data][product_data][name]', appt.service_name || 'Appointment');
    params.append('line_items[0][price_data][product_data][description]', `Booking on ${appt.date} at ${appt.start_time}`);
    params.append('line_items[0][quantity]', '1');
    params.append('success_url', `${baseUrl}/public/booking/${apptId}?token=${token}&paid=1`);
    params.append('cancel_url', `${baseUrl}/public/booking/${apptId}?token=${token}`);
    params.append('client_reference_id', apptId);
    if (appt.customer_email) params.append('customer_email', appt.customer_email);
    params.append('metadata[appointment_id]', apptId);
    params.append('metadata[tenant_id]', appt.tenant_id);

    const stripeResp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const session = await stripeResp.json() as any;
    if (!stripeResp.ok) {
      slog('error', 'Stripe checkout failed (public)', { error: session.error?.message });
      return json({ error: 'Payment system error' }, 502);
    }

    await c.env.DB.prepare("UPDATE appointments SET stripe_checkout_id=?, payment_status='pending', updated_at=datetime('now') WHERE id=?")
      .bind(session.id, apptId).run();

    return Response.redirect(session.url, 303);
  } catch (e: any) {
    slog('error', 'Public pay redirect failed', { error: e?.message });
    return json({ error: 'Internal error' }, 500);
  }
});

// POST /webhooks/stripe — Stripe webhook handler with signature verification
app.post('/webhooks/stripe', async (c) => {
  try {
    if (!c.env.STRIPE_WEBHOOK_SECRET) return json({ error: 'Webhook secret not configured' }, 503);
    const sigHeader = c.req.header('stripe-signature') || '';
    const rawBody = await c.req.text();

    // Parse signature header: t=timestamp,v1=signature
    const parts: Record<string, string> = {};
    for (const part of sigHeader.split(',')) {
      const [k, v] = part.split('=', 2);
      if (k && v) parts[k.trim()] = v.trim();
    }
    const timestamp = parts['t'];
    const v1Sig = parts['v1'];
    if (!timestamp || !v1Sig) return json({ error: 'Invalid signature format' }, 400);

    // Verify timestamp tolerance (5 minutes)
    const ts = parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > 300) {
      slog('warn', 'Stripe webhook timestamp out of tolerance', { diff: Math.abs(now - ts) });
      return json({ error: 'Timestamp outside tolerance' }, 400);
    }

    // Verify signature: HMAC-SHA256 of "timestamp.rawBody"
    const signedPayload = `${timestamp}.${rawBody}`;
    const expectedSig = await hmacSign(c.env.STRIPE_WEBHOOK_SECRET, signedPayload);
    // Constant-time comparison
    if (expectedSig.length !== v1Sig.length) return json({ error: 'Invalid signature' }, 401);
    let mismatch = 0;
    for (let i = 0; i < expectedSig.length; i++) mismatch |= expectedSig.charCodeAt(i) ^ v1Sig.charCodeAt(i);
    if (mismatch !== 0) {
      slog('warn', 'Stripe webhook signature mismatch');
      return json({ error: 'Invalid signature' }, 401);
    }

    const event = JSON.parse(rawBody) as { type: string; data: { object: any } };
    slog('info', 'Stripe webhook received', { type: event.type });

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const apptId = session.metadata?.appointment_id || session.client_reference_id;
      if (apptId) {
        await c.env.DB.prepare(
          "UPDATE appointments SET payment_status='paid', stripe_payment_id=?, paid_at=datetime('now'), updated_at=datetime('now') WHERE id=?"
        ).bind(session.payment_intent || session.id, apptId).run();
        // Update customer total_spent
        const appt = await c.env.DB.prepare('SELECT tenant_id, customer_id, price FROM appointments WHERE id=?').bind(apptId).first<any>();
        if (appt) {
          await c.env.DB.prepare("UPDATE customers SET total_spent=total_spent+?, updated_at=datetime('now') WHERE id=? AND tenant_id=?")
            .bind(appt.price || 0, appt.customer_id, appt.tenant_id).run();
          await logAct(c.env.DB, appt.tenant_id, 'appointment', apptId, 'payment_received', `Stripe payment ${session.payment_intent || session.id} — $${((session.amount_total || 0) / 100).toFixed(2)}`);
        }
        slog('info', 'Payment recorded', { appointment_id: apptId, payment_intent: session.payment_intent });
      }
    } else if (event.type === 'checkout.session.expired') {
      const session = event.data.object;
      const apptId = session.metadata?.appointment_id || session.client_reference_id;
      if (apptId) {
        await c.env.DB.prepare("UPDATE appointments SET payment_status='expired', updated_at=datetime('now') WHERE id=? AND payment_status='pending'")
          .bind(apptId).run();
        slog('info', 'Checkout expired', { appointment_id: apptId });
      }
    }

    return json({ received: true });
  } catch (e: any) {
    slog('error', 'Stripe webhook processing failed', { error: e?.message });
    return json({ error: 'Webhook processing failed' }, 500);
  }
});

// ═══════════════ WAITLIST ═══════════════
app.get('/waitlist', async (c) => {
  try {
    const r = await c.env.DB.prepare("SELECT w.*, c.name as customer_name, s.name as service_name FROM waitlist w LEFT JOIN customers c ON w.customer_id=c.id LEFT JOIN services s ON w.service_id=s.id WHERE w.tenant_id=? AND w.status='waiting' ORDER BY w.created_at").bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /waitlist', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/waitlist', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO waitlist (id,tenant_id,customer_id,service_id,staff_id,preferred_date,preferred_time) VALUES (?,?,?,?,?,?,?)')
      .bind(id, t, b.customer_id, b.service_id, b.staff_id||null, b.preferred_date||null, b.preferred_time||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /waitlist', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.delete('/waitlist/:id', async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM waitlist WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
    return json({ removed: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'DELETE /waitlist/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ RECURRING SCHEDULES ═══════════════
app.get('/recurring', async (c) => {
  try {
    const r = await c.env.DB.prepare("SELECT r.*, c.name as customer_name, s.name as service_name, st.name as staff_name FROM recurring_schedules r LEFT JOIN customers c ON r.customer_id=c.id LEFT JOIN services s ON r.service_id=s.id LEFT JOIN staff st ON r.staff_id=st.id WHERE r.tenant_id=? AND r.status='active' ORDER BY r.day_of_week").bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /recurring', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/recurring', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO recurring_schedules (id,tenant_id,customer_id,staff_id,service_id,location_id,day_of_week,start_time,frequency,interval_value,start_date,end_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.customer_id, b.staff_id, b.service_id, b.location_id||null, b.day_of_week, b.start_time, b.frequency||'weekly', b.interval_value||1, b.start_date, b.end_date||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /recurring', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.patch('/recurring/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare('UPDATE recurring_schedules SET status=coalesce(?,status),end_date=coalesce(?,end_date) WHERE id=? AND tenant_id=?')
      .bind(b.status||null, b.end_date||null, c.req.param('id'), tid(c)).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'PATCH /recurring/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ REVIEWS ═══════════════
app.get('/reviews', async (c) => {
  try {
    const t = tid(c); const staffId = c.req.query('staff_id');
    let q = 'SELECT r.*, c.name as customer_name, s.name as staff_name FROM reviews r LEFT JOIN customers c ON r.customer_id=c.id LEFT JOIN staff s ON r.staff_id=s.id WHERE r.tenant_id=?'; const p: string[] = [t];
    if (staffId) { q += ' AND r.staff_id=?'; p.push(staffId); }
    q += ' ORDER BY r.created_at DESC LIMIT 100';
    return json((await c.env.DB.prepare(q).bind(...p).all()).results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /reviews', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});
app.post('/reviews', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    const appt = await c.env.DB.prepare('SELECT staff_id FROM appointments WHERE id=? AND tenant_id=?').bind(b.appointment_id, t).first() as any;
    if (!appt) return json({ error: 'Appointment not found' }, 404);
    await c.env.DB.prepare('INSERT INTO reviews (id,tenant_id,appointment_id,customer_id,staff_id,rating,comment) VALUES (?,?,?,?,?,?,?)')
      .bind(id, t, b.appointment_id, b.customer_id, appt.staff_id, b.rating, b.comment||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /reviews', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ AI FEATURES ═══════════════
app.post('/ai/no-show-risk', async (c) => {
  try {
    const t = tid(c); const b = await c.req.json() as { customer_id: string };
    const cust = await c.env.DB.prepare('SELECT * FROM customers WHERE id=? AND tenant_id=?').bind(b.customer_id, t).first() as any;
    if (!cust) return json({ error: 'Customer not found' }, 404);
    const history = await c.env.DB.prepare("SELECT date, status, start_time FROM appointments WHERE customer_id=? AND tenant_id=? ORDER BY date DESC LIMIT 20").bind(b.customer_id, t).all();
    try {
    const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ engine_id: 'FN-01', query: `Analyze no-show risk for customer: ${cust.name}. Total bookings: ${cust.total_bookings}. No-shows: ${cust.no_show_count}. No-show rate: ${cust.total_bookings > 0 ? ((cust.no_show_count/cust.total_bookings)*100).toFixed(1) : 0}%. Recent appointments: ${JSON.stringify(history.results?.slice(0,10))}. Predict no-show probability and recommend: require deposit, send extra reminders, or no action needed.` }),
    });
    const ai = await aiRes.json() as any;
    return json({ customer: cust.name, no_show_rate: cust.total_bookings > 0 ? (cust.no_show_count/cust.total_bookings*100).toFixed(1) : 0, analysis: ai.response || ai });
  } catch { return json({ customer: cust.name, no_show_rate: cust.total_bookings > 0 ? (cust.no_show_count/cust.total_bookings*100).toFixed(1)+'%' : 'N/A', analysis: 'AI unavailable' }); }
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /ai/no-show-risk', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/ai/scheduling-insights', async (c) => {
  try {
    const t = tid(c);
    const [byDay, byHour, noShows, utilization] = await Promise.all([
      c.env.DB.prepare("SELECT strftime('%w', date) as day, COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND date>=date('now','-90 days') GROUP BY day ORDER BY day").bind(t).all(),
      c.env.DB.prepare("SELECT substr(start_time,1,2) as hour, COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND date>=date('now','-90 days') GROUP BY hour ORDER BY hour").bind(t).all(),
      c.env.DB.prepare("SELECT COUNT(CASE WHEN status='no_show' THEN 1 END)*100.0/COUNT(*) as rate FROM appointments WHERE tenant_id=? AND date>=date('now','-90 days')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as total FROM appointments WHERE tenant_id=? AND date>=date('now','-30 days') AND status='completed'").bind(t).first(),
    ]);
    try {
      const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine_id: 'FN-01', query: `Analyze scheduling patterns. Bookings by day of week: ${JSON.stringify(byDay.results)}. By hour: ${JSON.stringify(byHour.results)}. No-show rate: ${(noShows as any)?.rate?.toFixed(1) || 0}%. Monthly completions: ${(utilization as any)?.total || 0}. Suggest: optimal hours, staffing adjustments, overbooking strategy, and demand forecasting.` }),
      });
      const ai = await aiRes.json() as any;
      return json({ by_day: byDay.results, by_hour: byHour.results, no_show_rate: (noShows as any)?.rate, insights: ai.response || ai });
    } catch { return json({ by_day: byDay.results, by_hour: byHour.results, no_show_rate: (noShows as any)?.rate, insights: 'AI unavailable' }); }
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'POST /ai/scheduling-insights', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ ANALYTICS ═══════════════
app.get('/analytics/overview', async (c) => {
  try {
    const t = tid(c);
    const [today, week, month, revenue, noShows, topServices, topStaff] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND date=date('now') AND status NOT IN ('cancelled')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND date>=date('now','weekday 0','-7 days') AND date<=date('now') AND status NOT IN ('cancelled')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND date>=date('now','-30 days') AND status NOT IN ('cancelled')").bind(t).first(),
      c.env.DB.prepare("SELECT SUM(price) as sum FROM appointments WHERE tenant_id=? AND status='completed' AND date>=date('now','-30 days')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND status='no_show' AND date>=date('now','-30 days')").bind(t).first(),
      c.env.DB.prepare("SELECT s.name, COUNT(*) as cnt FROM appointments a JOIN services s ON a.service_id=s.id WHERE a.tenant_id=? AND a.date>=date('now','-30 days') AND a.status NOT IN ('cancelled') GROUP BY a.service_id ORDER BY cnt DESC LIMIT 5").bind(t).all(),
      c.env.DB.prepare("SELECT st.name, COUNT(*) as cnt, AVG(r.rating) as avg_rating FROM appointments a JOIN staff st ON a.staff_id=st.id LEFT JOIN reviews r ON r.staff_id=st.id AND r.tenant_id=a.tenant_id WHERE a.tenant_id=? AND a.date>=date('now','-30 days') AND a.status='completed' GROUP BY a.staff_id ORDER BY cnt DESC LIMIT 5").bind(t).all(),
    ]);
    return json({
      today: (today as any)?.cnt || 0,
      this_week: (week as any)?.cnt || 0,
      this_month: (month as any)?.cnt || 0,
      revenue_30d: (revenue as any)?.sum || 0,
      no_shows_30d: (noShows as any)?.cnt || 0,
      top_services: topServices.results,
      top_staff: topStaff.results,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /analytics/overview', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/analytics/daily', async (c) => {
  try {
    const t = tid(c); const from = c.req.query('from') || new Date(Date.now()-30*86400000).toISOString().split('T')[0];
    const r = await c.env.DB.prepare("SELECT date, COUNT(*) as bookings, SUM(CASE WHEN status='completed' THEN price ELSE 0 END) as revenue, SUM(CASE WHEN status='no_show' THEN 1 ELSE 0 END) as no_shows, SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) as cancellations FROM appointments WHERE tenant_id=? AND date>=? GROUP BY date ORDER BY date").bind(t, from).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /analytics/daily', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ ACTIVITY LOG ═══════════════
app.get('/activity', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM activity_log WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /activity', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ CRON: REMINDERS + RECURRING ═══════════════
app.get('/__cron', async (c) => {
  try {
    const results: string[] = [];
    // Mark past unconfirmed as no-show
    const noShows = await c.env.DB.prepare("UPDATE appointments SET status='no_show',no_show_at=datetime('now') WHERE status='confirmed' AND date<date('now') AND end_time<time('now')").run();
    results.push(`Marked ${noShows.meta.changes} past appointments as no-show`);

    // Generate recurring appointments for next 2 weeks
    const recs = await c.env.DB.prepare("SELECT * FROM recurring_schedules WHERE status='active'").all();
    for (const rec of recs.results as any[]) {
      const svc = await c.env.DB.prepare('SELECT duration_minutes FROM services WHERE id=?').bind(rec.service_id).first() as any;
      const endTime = addMinutes(rec.start_time, svc?.duration_minutes || 60);
      // Check next 14 days for matching day_of_week
      for (let d = 0; d < 14; d++) {
        const date = new Date(Date.now() + d * 86400000);
        if (date.getDay() !== rec.day_of_week) continue;
        const dateStr = date.toISOString().split('T')[0];
        if (dateStr < rec.start_date) continue;
        if (rec.end_date && dateStr > rec.end_date) continue;
        // Check if already exists
        const exists = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE tenant_id=? AND customer_id=? AND service_id=? AND date=? AND recurring_id=?").bind(rec.tenant_id, rec.customer_id, rec.service_id, dateStr, rec.id).first() as any;
        if (exists?.cnt > 0) continue;
        const id = uid();
        await c.env.DB.prepare("INSERT INTO appointments (id,tenant_id,customer_id,staff_id,service_id,location_id,status,start_time,end_time,date,is_recurring,recurring_id,source) VALUES (?,?,?,?,?,?,'confirmed',?,?,?,1,?,'recurring')")
          .bind(id, rec.tenant_id, rec.customer_id, rec.staff_id, rec.service_id, rec.location_id||null, rec.start_time, endTime, dateStr, rec.id).run();
        await c.env.DB.prepare('UPDATE recurring_schedules SET appointments_created=appointments_created+1 WHERE id=?').bind(rec.id).run();
        results.push(`Created recurring appointment for ${dateStr}`);
      }
    }
    return json({ cron: 'complete', results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'GET /__cron', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ── Helpers ──
function timesOverlap(s1: string, e1: string, s2: string, e2: string): boolean {
  return s1 < e2 && s2 < e1;
}
function addMinutes(time: string, mins: number): string {
  const [h, m] = time.split(':').map(Number);
  const total = h * 60 + m + mins;
  return `${String(Math.floor(total/60)).padStart(2,'0')}:${String(total%60).padStart(2,'0')}`;
}
async function logAct(db: D1Database, t: string, et: string, eid: string, action: string, details: string) {
  try {
    await db.prepare('INSERT INTO activity_log (id,tenant_id,entity_type,entity_id,action,details) VALUES (?,?,?,?,?,?)').bind(uid(), t, et, eid, action, details).run();
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'logAct', error: e?.message }));
  }
}

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-booking] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    try {
      const results: string[] = [];
      const noShows = await env.DB.prepare("UPDATE appointments SET status='no_show',no_show_at=datetime('now') WHERE status='confirmed' AND date<date('now')").run();
      results.push(`No-shows: ${noShows.meta.changes}`);
      const recs = await env.DB.prepare("SELECT * FROM recurring_schedules WHERE status='active'").all();
      for (const rec of recs.results as any[]) {
        const svc = await env.DB.prepare('SELECT duration_minutes FROM services WHERE id=?').bind(rec.service_id).first() as any;
        const endTime = addMinutes(rec.start_time, svc?.duration_minutes||60);
        for (let d = 0; d < 14; d++) {
          const dt = new Date(Date.now()+d*86400000);
          if (dt.getDay() !== rec.day_of_week) continue;
          const ds = dt.toISOString().split('T')[0];
          if (ds < rec.start_date || (rec.end_date && ds > rec.end_date)) continue;
          // Duplicate protection: check by recurring_id + date (simpler, faster)
          const exists = await env.DB.prepare(
            "SELECT id FROM appointments WHERE recurring_id = ? AND date = ?"
          ).bind(rec.id, ds).first();
          if (exists) continue;
          await env.DB.prepare("INSERT INTO appointments (id,tenant_id,customer_id,staff_id,service_id,location_id,status,start_time,end_time,date,is_recurring,recurring_id,source) VALUES (?,?,?,?,?,?,'confirmed',?,?,?,1,?,'recurring')")
            .bind(uid(), rec.tenant_id, rec.customer_id, rec.staff_id, rec.service_id, rec.location_id||null, rec.start_time, endTime, ds, rec.id).run();
        }
      }
      console.log(JSON.stringify({ event: 'cron', results }));
    } catch (e: any) {
      console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-booking', message: 'D1 query failed', endpoint: 'scheduled', error: e?.message }));
    }
  },
};
