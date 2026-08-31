# SIH26106 Backend — Phase 7

Phase 7 implements the passive **URL, Domain and IP analysis services** from the SIH26106 plan.

## Included
- URL normalization and heuristic analysis
- IP-based URLs, shorteners, Punycode, deep subdomains, credential paths, encoded URLs and unusual ports
- Configurable trusted-brand look-alike detection
- Punycode and subdomain domain checks
- IPv4/IPv6, private/public/reserved/loopback/link-local classification
- No arbitrary URL fetching; this avoids SSRF
- PostgreSQL persistence using the existing `urls`, `domains` and `ip_addresses` tables
- JWT + analyst/admin authorization

## Endpoint
`POST /api/v1/emails/{email_id}/intelligence`

The endpoint analyzes already-parsed records. Run Phase 5 parsing first.

## Trusted brands
Set `TRUSTED_BRANDS=Brand:domain,Brand2:domain2` in `.env`.
If not configured, `target_brand` remains null.

## External intelligence
External URL/domain/IP reputation is intentionally optional. This phase does not invent reputation, age, registrar, VPN, proxy, Tor, or geolocation values.

## Security
The service never requests arbitrary URLs extracted from an email. Suspicious URLs are analyzed as strings only.
