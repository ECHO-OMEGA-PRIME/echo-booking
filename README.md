# Echo Booking

> Multi-tenant booking & scheduling platform for ECHO Prime (v2.0.0). Staff,
> services, locations, availability, recurring appointments, waitlists, reviews,
> Stripe payments, and AI scheduling insights — a Hono app on Cloudflare Workers
> with a cron trigger.

Private to Echo Prime Technologies.

## Model

A **tenant** has **locations** and **staff**; staff offer **services** with
**availability** and **time-off**. **Customers** book **appointments** (one-off or
**recurring**), join a **waitlist** when full, and leave **reviews**. Appointments
move through a lifecycle and can be paid via Stripe.

## API (auth: `X-Echo-API-Key`)

**Appointments** — `GET /appointments`, `GET /appointments/:id`, `POST /appointments`,
lifecycle: `POST /appointments/:id/{cancel,complete,no-show,reschedule,checkout,payment-link}`
**Recurring** — `POST /recurring`, `PATCH /recurring/:id`
**Availability & time-off** — `GET|POST /availability`, `DELETE /availability/:id`,
`POST /time-off`
**Staff & services** — `POST /staff`, `POST /staff/:id/services`, `POST /services`,
`PUT /services/:id`, `POST /locations`
**Customers & waitlist** — `GET /customers`, `GET /customers/:id`, `POST /customers`,
`POST /waitlist`, `DELETE /waitlist/:id`
**Reviews** — `POST /reviews`
**AI** — `POST /ai/no-show-risk`, `POST /ai/scheduling-insights`
**Payments (Stripe)** — `POST /appointments/:id/{checkout,payment-link}`,
`POST /webhooks/stripe`
**Tenancy** — `POST /tenants`, `PUT /tenants/:id`
**Insights & meta** — `GET /analytics/overview`, `GET /analytics/daily`,
`GET /activity`, `GET /`, `GET /health`
**Cron** — `GET /__cron` (scheduled reminders / maintenance)

## Develop

```bash
npm install
npx wrangler dev       # local Worker
npx wrangler deploy    # deploy
```

Stripe keys and the D1 binding live in `wrangler.toml` / the Cloudflare dashboard.
`/webhooks/stripe` verifies the Stripe signature. Never commit secrets.

## License

Proprietary — © Echo Prime Technologies. All rights reserved.
