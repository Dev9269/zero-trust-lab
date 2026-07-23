# Rate Limiting

The gateway nginx configuration applies rate limiting to protect backend services.

## Limits

- **API endpoints** (`/api/`): 30 requests/minute per IP
- **Auth endpoints** (`/oauth2/`): 10 requests/minute per IP
- **Static content** (`/public`): 100 requests/minute per IP
- **Admin dashboard** (`/admin`): 20 requests/minute per IP

## Configuration

Rate limit zones are defined in `gateway/nginx/conf.d/ztlab.conf`:

```
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
```

## Exceeding the limit

Clients that exceed the rate limit receive HTTP 429 (Too Many Requests) with a `Retry-After` header.

## Production

In production, replace nginx rate limiting with a dedicated API gateway
(Kong, Envoy) for distributed rate limiting across multiple gateway instances.
