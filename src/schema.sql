-- Echo Booking v1.0.0 Schema
-- AI-powered appointment scheduling system

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  timezone TEXT DEFAULT 'America/Chicago',
  currency TEXT DEFAULT 'USD',
  booking_window_days INTEGER DEFAULT 60,
  min_notice_hours INTEGER DEFAULT 1,
  cancellation_hours INTEGER DEFAULT 24,
  buffer_minutes INTEGER DEFAULT 0,
  max_daily_bookings INTEGER DEFAULT 0,
  allow_waitlist INTEGER DEFAULT 1,
  require_approval INTEGER DEFAULT 0,
  confirmation_message TEXT,
  cancellation_policy TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS locations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  phone TEXT,
  timezone TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_locations_tenant ON locations(tenant_id);

CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  duration_minutes INTEGER DEFAULT 60,
  price REAL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  color TEXT DEFAULT '#14b8a6',
  category TEXT,
  buffer_before INTEGER DEFAULT 0,
  buffer_after INTEGER DEFAULT 0,
  max_attendees INTEGER DEFAULT 1,
  is_active INTEGER DEFAULT 1,
  sort_order INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_services_tenant ON services(tenant_id);

CREATE TABLE IF NOT EXISTS staff (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  role TEXT DEFAULT 'staff',
  avatar_url TEXT,
  bio TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_staff_tenant ON staff(tenant_id);

CREATE TABLE IF NOT EXISTS staff_services (
  staff_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  PRIMARY KEY (staff_id, service_id),
  FOREIGN KEY (staff_id) REFERENCES staff(id),
  FOREIGN KEY (service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS availability (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  day_of_week INTEGER NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  location_id TEXT,
  is_active INTEGER DEFAULT 1,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE INDEX IF NOT EXISTS idx_availability_staff ON availability(tenant_id, staff_id);
CREATE INDEX IF NOT EXISTS idx_availability_day ON availability(tenant_id, day_of_week);

CREATE TABLE IF NOT EXISTS time_off (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  reason TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE INDEX IF NOT EXISTS idx_timeoff_staff ON time_off(tenant_id, staff_id);

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  notes TEXT,
  no_show_count INTEGER DEFAULT 0,
  total_bookings INTEGER DEFAULT 0,
  total_spent REAL DEFAULT 0,
  last_visit_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_customers_tenant ON customers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(tenant_id, email);

CREATE TABLE IF NOT EXISTS appointments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  location_id TEXT,
  status TEXT DEFAULT 'confirmed',
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  date TEXT NOT NULL,
  price REAL DEFAULT 0,
  notes TEXT,
  customer_notes TEXT,
  internal_notes TEXT,
  is_recurring INTEGER DEFAULT 0,
  recurring_id TEXT,
  reminder_sent INTEGER DEFAULT 0,
  source TEXT DEFAULT 'manual',
  cancellation_reason TEXT,
  cancelled_at TEXT,
  no_show_at TEXT,
  completed_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (customer_id) REFERENCES customers(id),
  FOREIGN KEY (staff_id) REFERENCES staff(id),
  FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_appt_tenant ON appointments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_appt_date ON appointments(tenant_id, date);
CREATE INDEX IF NOT EXISTS idx_appt_staff ON appointments(tenant_id, staff_id, date);
CREATE INDEX IF NOT EXISTS idx_appt_customer ON appointments(tenant_id, customer_id);
CREATE INDEX IF NOT EXISTS idx_appt_status ON appointments(tenant_id, status);

CREATE TABLE IF NOT EXISTS recurring_schedules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  location_id TEXT,
  day_of_week INTEGER NOT NULL,
  start_time TEXT NOT NULL,
  frequency TEXT DEFAULT 'weekly',
  interval_value INTEGER DEFAULT 1,
  start_date TEXT NOT NULL,
  end_date TEXT,
  status TEXT DEFAULT 'active',
  appointments_created INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_recurring_tenant ON recurring_schedules(tenant_id);

CREATE TABLE IF NOT EXISTS waitlist (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  staff_id TEXT,
  preferred_date TEXT,
  preferred_time TEXT,
  status TEXT DEFAULT 'waiting',
  notified_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_waitlist_tenant ON waitlist(tenant_id);
CREATE INDEX IF NOT EXISTS idx_waitlist_service ON waitlist(tenant_id, service_id);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  appointment_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  rating INTEGER NOT NULL,
  comment TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (appointment_id) REFERENCES appointments(id)
);
CREATE INDEX IF NOT EXISTS idx_reviews_tenant ON reviews(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reviews_staff ON reviews(tenant_id, staff_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
