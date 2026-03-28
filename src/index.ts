/**
 * Echo Booking v1.0.0 — AI-Powered Appointment Scheduling
 * Cloudflare Worker with Hono, D1, KV, service bindings
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env { DB: D1Database; CACHE: KVNamespace; ENGINE_RUNTIME: Fetcher; SHARED_BRAIN: Fetcher; ECHO_API_KEY?: string; }
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
app.use('*', cors({ origin: '*', allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Echo-API-Key'] }));

const uid = () => crypto.randomUUID();
const sanitize = (s: string, max = 2000) => s?.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max) ?? '';
const sanitizeBody = (o: Record<string, unknown>) => { const r: Record<string, unknown> = {}; for (const [k, v] of Object.entries(o)) r[k] = typeof v === 'string' ? sanitize(v) : v; return r; };
const tid = (c: any) => c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '';
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } });

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-booking', version: '1.0.0', msg, ...data };
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
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path.startsWith('/public/')) return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

app.get('/', (c) => c.redirect('/health'));
app.get('/health', (c) => json({ status: 'ok', service: 'echo-booking', version: '1.0.0', time: new Date().toISOString() }));

// ═══════════════ TENANTS ═══════════════
app.post('/tenants', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO tenants (id,name,email,phone,timezone,currency,booking_window_days,min_notice_hours,cancellation_hours,buffer_minutes,max_daily_bookings,allow_waitlist,require_approval,confirmation_message,cancellation_policy) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, b.name, b.email||null, b.phone||null, b.timezone||'America/Chicago', b.currency||'USD', b.booking_window_days||60, b.min_notice_hours||1, b.cancellation_hours||24, b.buffer_minutes||0, b.max_daily_bookings||0, b.allow_waitlist??1, b.require_approval||0, b.confirmation_message||null, b.cancellation_policy||null).run();
  return json({ id }, 201);
});
app.get('/tenants/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});
app.put('/tenants/:id', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare('UPDATE tenants SET name=coalesce(?,name),email=coalesce(?,email),phone=coalesce(?,phone),timezone=coalesce(?,timezone),booking_window_days=coalesce(?,booking_window_days),min_notice_hours=coalesce(?,min_notice_hours),cancellation_hours=coalesce(?,cancellation_hours),buffer_minutes=coalesce(?,buffer_minutes),max_daily_bookings=coalesce(?,max_daily_bookings),allow_waitlist=coalesce(?,allow_waitlist),require_approval=coalesce(?,require_approval),updated_at=datetime(\'now\') WHERE id=?')
    .bind(b.name||null, b.email||null, b.phone||null, b.timezone||null, b.booking_window_days??null, b.min_notice_hours??null, b.cancellation_hours??null, b.buffer_minutes??null, b.max_daily_bookings??null, b.allow_waitlist??null, b.require_approval??null, c.req.param('id')).run();
  return json({ updated: true });
});

// ═══════════════ LOCATIONS ═══════════════
app.get('/locations', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM locations WHERE tenant_id=? AND is_active=1 ORDER BY name').bind(tid(c)).all();
  return json(r.results);
});
app.post('/locations', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO locations (id,tenant_id,name,address,city,state,zip,phone,timezone) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(id, t, b.name, b.address||null, b.city||null, b.state||null, b.zip||null, b.phone||null, b.timezone||null).run();
  return json({ id }, 201);
});

// ═══════════════ SERVICES ═══════════════
app.get('/services', async (c) => {
  const t = tid(c); const cat = c.req.query('category');
  let q = 'SELECT * FROM services WHERE tenant_id=? AND is_active=1'; const p: string[] = [t];
  if (cat) { q += ' AND category=?'; p.push(cat); }
  q += ' ORDER BY sort_order, name';
  return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/services', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO services (id,tenant_id,name,description,duration_minutes,price,currency,color,category,buffer_before,buffer_after,max_attendees,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, t, b.name, b.description||null, b.duration_minutes||60, b.price||0, b.currency||'USD', b.color||'#14b8a6', b.category||null, b.buffer_before||0, b.buffer_after||0, b.max_attendees||1, b.sort_order||0).run();
  return json({ id }, 201);
});
app.put('/services/:id', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare('UPDATE services SET name=coalesce(?,name),description=coalesce(?,description),duration_minutes=coalesce(?,duration_minutes),price=coalesce(?,price),color=coalesce(?,color),category=coalesce(?,category),buffer_before=coalesce(?,buffer_before),buffer_after=coalesce(?,buffer_after),max_attendees=coalesce(?,max_attendees),is_active=coalesce(?,is_active) WHERE id=? AND tenant_id=?')
    .bind(b.name||null, b.description||null, b.duration_minutes??null, b.price??null, b.color||null, b.category||null, b.buffer_before??null, b.buffer_after??null, b.max_attendees??null, b.is_active??null, c.req.param('id'), tid(c)).run();
  return json({ updated: true });
});

// ═══════════════ STAFF ═══════════════
app.get('/staff', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM staff WHERE tenant_id=? AND is_active=1 ORDER BY name').bind(tid(c)).all();
  return json(r.results);
});
app.post('/staff', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO staff (id,tenant_id,name,email,phone,role,avatar_url,bio) VALUES (?,?,?,?,?,?,?,?)')
    .bind(id, t, b.name, b.email||null, b.phone||null, b.role||'staff', b.avatar_url||null, b.bio||null).run();
  return json({ id }, 201);
});
app.get('/staff/:id', async (c) => {
  const staff = await c.env.DB.prepare('SELECT * FROM staff WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
  if (!staff) return json({ error: 'Not found' }, 404);
  const svcs = await c.env.DB.prepare('SELECT s.* FROM services s JOIN staff_services ss ON s.id=ss.service_id WHERE ss.staff_id=? AND ss.tenant_id=?').bind(c.req.param('id'), tid(c)).all();
  const avail = await c.env.DB.prepare('SELECT * FROM availability WHERE staff_id=? AND tenant_id=? AND is_active=1 ORDER BY day_of_week, start_time').bind(c.req.param('id'), tid(c)).all();
  const reviews = await c.env.DB.prepare('SELECT AVG(rating) as avg_rating, COUNT(*) as review_count FROM reviews WHERE staff_id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
  return json({ ...staff, services: svcs.results, availability: avail.results, avg_rating: (reviews as any)?.avg_rating, review_count: (reviews as any)?.review_count });
});
// Assign services to staff
app.post('/staff/:id/services', async (c) => {
  const t = tid(c); const b = await c.req.json() as { service_ids: string[] };
  await c.env.DB.prepare('DELETE FROM staff_services WHERE staff_id=? AND tenant_id=?').bind(c.req.param('id'), t).run();
  for (const svcId of b.service_ids) {
    await c.env.DB.prepare('INSERT INTO staff_services (staff_id,service_id,tenant_id) VALUES (?,?,?)').bind(c.req.param('id'), svcId, t).run();
  }
  return json({ assigned: b.service_ids.length });
});

// ═══════════════ AVAILABILITY ═══════════════
app.get('/availability', async (c) => {
  const t = tid(c); const staffId = c.req.query('staff_id');
  let q = 'SELECT a.*, s.name as staff_name FROM availability a LEFT JOIN staff s ON a.staff_id=s.id WHERE a.tenant_id=? AND a.is_active=1';
  const p: string[] = [t];
  if (staffId) { q += ' AND a.staff_id=?'; p.push(staffId); }
  q += ' ORDER BY a.day_of_week, a.start_time';
  return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/availability', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO availability (id,tenant_id,staff_id,day_of_week,start_time,end_time,location_id) VALUES (?,?,?,?,?,?,?)')
    .bind(id, t, b.staff_id, b.day_of_week, b.start_time, b.end_time, b.location_id||null).run();
  return json({ id }, 201);
});
app.delete('/availability/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM availability WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
  return json({ deleted: true });
});

// ═══════════════ TIME OFF ═══════════════
app.get('/time-off', async (c) => {
  const t = tid(c); const staffId = c.req.query('staff_id');
  let q = 'SELECT t.*, s.name as staff_name FROM time_off t LEFT JOIN staff s ON t.staff_id=s.id WHERE t.tenant_id=?'; const p: string[] = [t];
  if (staffId) { q += ' AND t.staff_id=?'; p.push(staffId); }
  q += ' ORDER BY t.start_date DESC';
  return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/time-off', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO time_off (id,tenant_id,staff_id,start_date,end_date,reason) VALUES (?,?,?,?,?,?)')
    .bind(id, t, b.staff_id, b.start_date, b.end_date, b.reason||null).run();
  return json({ id }, 201);
});

// ═══════════════ CUSTOMERS ═══════════════
app.get('/customers', async (c) => {
  const t = tid(c); const search = c.req.query('search');
  let q = 'SELECT * FROM customers WHERE tenant_id=?'; const p: string[] = [t];
  if (search) { q += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'; const s = `%${sanitize(search,100)}%`; p.push(s,s,s); }
  q += ' ORDER BY name LIMIT 200';
  return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/customers', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO customers (id,tenant_id,name,email,phone,notes) VALUES (?,?,?,?,?,?)')
    .bind(id, t, b.name, b.email||null, b.phone||null, b.notes||null).run();
  return json({ id }, 201);
});
app.get('/customers/:id', async (c) => {
  const t = tid(c); const cust = await c.env.DB.prepare('SELECT * FROM customers WHERE id=? AND tenant_id=?').bind(c.req.param('id'), t).first();
  if (!cust) return json({ error: 'Not found' }, 404);
  const appts = await c.env.DB.prepare('SELECT a.*, s.name as service_name, st.name as staff_name FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id WHERE a.customer_id=? AND a.tenant_id=? ORDER BY a.date DESC LIMIT 20').bind(c.req.param('id'), t).all();
  return json({ ...cust, appointments: appts.results });
});

// ═══════════════ APPOINTMENTS ═══════════════
// Get available slots for a service + staff on a date
app.get('/slots', async (c) => {
  const t = tid(c); const date = c.req.query('date'); const serviceId = c.req.query('service_id'); const staffId = c.req.query('staff_id');
  if (!date || !serviceId) return json({ error: 'date and service_id required' }, 400);
  const service = await c.env.DB.prepare('SELECT * FROM services WHERE id=? AND tenant_id=?').bind(serviceId, t).first() as any;
  if (!service) return json({ error: 'Service not found' }, 404);
  const dayOfWeek = new Date(date + 'T12:00:00').getDay();
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
});

app.get('/appointments', async (c) => {
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
});

app.post('/appointments', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  // Get service for duration
  const svc = await c.env.DB.prepare('SELECT * FROM services WHERE id=? AND tenant_id=?').bind(b.service_id, t).first() as any;
  const endTime = (b.end_time as string) || addMinutes(b.start_time as string, svc?.duration_minutes || 60);
  const status = b.status || 'confirmed';
  await c.env.DB.prepare('INSERT INTO appointments (id,tenant_id,customer_id,staff_id,service_id,location_id,status,start_time,end_time,date,price,notes,customer_notes,internal_notes,source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, t, b.customer_id, b.staff_id, b.service_id, b.location_id||null, status, b.start_time, endTime, b.date, b.price||svc?.price||0, b.notes||null, b.customer_notes||null, b.internal_notes||null, b.source||'manual').run();
  // Update customer stats
  await c.env.DB.prepare('UPDATE customers SET total_bookings=total_bookings+1,updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(b.customer_id, t).run();
  await logAct(c.env.DB, t, 'appointment', id, 'booked', `Appointment booked for ${b.date} ${b.start_time}`);
  return json({ id, end_time: endTime }, 201);
});

app.get('/appointments/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT a.*, s.name as service_name, s.duration_minutes, st.name as staff_name, cu.name as customer_name, cu.email as customer_email, cu.phone as customer_phone FROM appointments a LEFT JOIN services s ON a.service_id=s.id LEFT JOIN staff st ON a.staff_id=st.id LEFT JOIN customers cu ON a.customer_id=cu.id WHERE a.id=? AND a.tenant_id=?').bind(c.req.param('id'), tid(c)).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});

// Cancel appointment
app.post('/appointments/:id/cancel', async (c) => {
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
      }
    }
  }
  await logAct(c.env.DB, t, 'appointment', c.req.param('id'), 'cancelled', b.reason||'Cancelled');
  return json({ cancelled: true, waitlist_notified: appt ? true : false });
});

// Complete appointment
app.post('/appointments/:id/complete', async (c) => {
  const t = tid(c);
  await c.env.DB.prepare("UPDATE appointments SET status='completed',completed_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), t).run();
  const appt = await c.env.DB.prepare('SELECT * FROM appointments WHERE id=?').bind(c.req.param('id')).first() as any;
  if (appt) {
    await c.env.DB.prepare('UPDATE customers SET total_spent=total_spent+?,last_visit_at=datetime(\'now\'),updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(appt.price||0, appt.customer_id, t).run();
  }
  return json({ completed: true });
});

// Mark no-show
app.post('/appointments/:id/no-show', async (c) => {
  const t = tid(c);
  await c.env.DB.prepare("UPDATE appointments SET status='no_show',no_show_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), t).run();
  const appt = await c.env.DB.prepare('SELECT customer_id FROM appointments WHERE id=?').bind(c.req.param('id')).first() as any;
  if (appt) {
    await c.env.DB.prepare('UPDATE customers SET no_show_count=no_show_count+1,updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?').bind(appt.customer_id, t).run();
  }
  return json({ marked: true });
});

// Reschedule
app.post('/appointments/:id/reschedule', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json());
  const svc = await c.env.DB.prepare('SELECT s.duration_minutes FROM appointments a JOIN services s ON a.service_id=s.id WHERE a.id=? AND a.tenant_id=?').bind(c.req.param('id'), t).first() as any;
  const endTime = (b.end_time as string) || addMinutes(b.start_time as string, svc?.duration_minutes||60);
  await c.env.DB.prepare("UPDATE appointments SET date=?,start_time=?,end_time=?,staff_id=coalesce(?,staff_id),status='confirmed',updated_at=datetime('now') WHERE id=? AND tenant_id=?")
    .bind(b.date, b.start_time, endTime, b.staff_id||null, c.req.param('id'), t).run();
  await logAct(c.env.DB, t, 'appointment', c.req.param('id'), 'rescheduled', `Rescheduled to ${b.date} ${b.start_time}`);
  return json({ rescheduled: true, end_time: endTime });
});

// ═══════════════ WAITLIST ═══════════════
app.get('/waitlist', async (c) => {
  const r = await c.env.DB.prepare("SELECT w.*, c.name as customer_name, s.name as service_name FROM waitlist w LEFT JOIN customers c ON w.customer_id=c.id LEFT JOIN services s ON w.service_id=s.id WHERE w.tenant_id=? AND w.status='waiting' ORDER BY w.created_at").bind(tid(c)).all();
  return json(r.results);
});
app.post('/waitlist', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO waitlist (id,tenant_id,customer_id,service_id,staff_id,preferred_date,preferred_time) VALUES (?,?,?,?,?,?,?)')
    .bind(id, t, b.customer_id, b.service_id, b.staff_id||null, b.preferred_date||null, b.preferred_time||null).run();
  return json({ id }, 201);
});
app.delete('/waitlist/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM waitlist WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
  return json({ removed: true });
});

// ═══════════════ RECURRING SCHEDULES ═══════════════
app.get('/recurring', async (c) => {
  const r = await c.env.DB.prepare("SELECT r.*, c.name as customer_name, s.name as service_name, st.name as staff_name FROM recurring_schedules r LEFT JOIN customers c ON r.customer_id=c.id LEFT JOIN services s ON r.service_id=s.id LEFT JOIN staff st ON r.staff_id=st.id WHERE r.tenant_id=? AND r.status='active' ORDER BY r.day_of_week").bind(tid(c)).all();
  return json(r.results);
});
app.post('/recurring', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO recurring_schedules (id,tenant_id,customer_id,staff_id,service_id,location_id,day_of_week,start_time,frequency,interval_value,start_date,end_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, t, b.customer_id, b.staff_id, b.service_id, b.location_id||null, b.day_of_week, b.start_time, b.frequency||'weekly', b.interval_value||1, b.start_date, b.end_date||null).run();
  return json({ id }, 201);
});
app.patch('/recurring/:id', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare('UPDATE recurring_schedules SET status=coalesce(?,status),end_date=coalesce(?,end_date) WHERE id=? AND tenant_id=?')
    .bind(b.status||null, b.end_date||null, c.req.param('id'), tid(c)).run();
  return json({ updated: true });
});

// ═══════════════ REVIEWS ═══════════════
app.get('/reviews', async (c) => {
  const t = tid(c); const staffId = c.req.query('staff_id');
  let q = 'SELECT r.*, c.name as customer_name, s.name as staff_name FROM reviews r LEFT JOIN customers c ON r.customer_id=c.id LEFT JOIN staff s ON r.staff_id=s.id WHERE r.tenant_id=?'; const p: string[] = [t];
  if (staffId) { q += ' AND r.staff_id=?'; p.push(staffId); }
  q += ' ORDER BY r.created_at DESC LIMIT 100';
  return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/reviews', async (c) => {
  const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
  const appt = await c.env.DB.prepare('SELECT staff_id FROM appointments WHERE id=? AND tenant_id=?').bind(b.appointment_id, t).first() as any;
  if (!appt) return json({ error: 'Appointment not found' }, 404);
  await c.env.DB.prepare('INSERT INTO reviews (id,tenant_id,appointment_id,customer_id,staff_id,rating,comment) VALUES (?,?,?,?,?,?,?)')
    .bind(id, t, b.appointment_id, b.customer_id, appt.staff_id, b.rating, b.comment||null).run();
  return json({ id }, 201);
});

// ═══════════════ AI FEATURES ═══════════════
app.post('/ai/no-show-risk', async (c) => {
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
});

app.post('/ai/scheduling-insights', async (c) => {
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
});

// ═══════════════ ANALYTICS ═══════════════
app.get('/analytics/overview', async (c) => {
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
});

app.get('/analytics/daily', async (c) => {
  const t = tid(c); const from = c.req.query('from') || new Date(Date.now()-30*86400000).toISOString().split('T')[0];
  const r = await c.env.DB.prepare("SELECT date, COUNT(*) as bookings, SUM(CASE WHEN status='completed' THEN price ELSE 0 END) as revenue, SUM(CASE WHEN status='no_show' THEN 1 ELSE 0 END) as no_shows, SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) as cancellations FROM appointments WHERE tenant_id=? AND date>=? GROUP BY date ORDER BY date").bind(t, from).all();
  return json(r.results);
});

// ═══════════════ ACTIVITY LOG ═══════════════
app.get('/activity', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM activity_log WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(tid(c)).all();
  return json(r.results);
});

// ═══════════════ CRON: REMINDERS + RECURRING ═══════════════
app.get('/__cron', async (c) => {
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
  await db.prepare('INSERT INTO activity_log (id,tenant_id,entity_type,entity_id,action,details) VALUES (?,?,?,?,?,?)').bind(uid(), t, et, eid, action, details).run();
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
        const ex = await env.DB.prepare("SELECT COUNT(*) as c FROM appointments WHERE tenant_id=? AND customer_id=? AND service_id=? AND date=? AND recurring_id=?").bind(rec.tenant_id, rec.customer_id, rec.service_id, ds, rec.id).first() as any;
        if (ex?.c > 0) continue;
        await env.DB.prepare("INSERT INTO appointments (id,tenant_id,customer_id,staff_id,service_id,location_id,status,start_time,end_time,date,is_recurring,recurring_id,source) VALUES (?,?,?,?,?,?,'confirmed',?,?,?,1,?,'recurring')")
          .bind(uid(), rec.tenant_id, rec.customer_id, rec.staff_id, rec.service_id, rec.location_id||null, rec.start_time, endTime, ds, rec.id).run();
      }
    }
    console.log(JSON.stringify({ event: 'cron', results }));
  },
};
