# Part 3: Incident Response Plan — IDOR Vulnerability Disclosure

## Scenario Recap
A support agent responsibly disclosed they accessed another company's customer records by modifying `company_id` in the web dashboard URL (`/customers/view?company_id=1234` → `1235`). This confirms active Broken Access Control vulnerability in production.

---

## 1. Immediate Actions (Next 60 Minutes)

| Time | Action | Owner | Why This Order Matters |
|------|--------|-------|------------------------|
| **T+0–5 min** | **Acknowledge & Isolate Reporter**<br>- Thank agent for responsible disclosure<br>- Request exact steps taken, timestamps, screenshots<br>- Instruct: "Do not test further; preserve browser history" | Security Lead | Prevents accidental evidence destruction; establishes trust for future disclosures |
| **T+5–15 min** | **Temporary Containment**<br>- Deploy AWS WAF rule blocking requests containing `company_id` parameter *except* from internal IP ranges<br>- **DO NOT** patch code yet (preserves evidence for root cause analysis)<br>- Notify engineering lead: "Incident declared; stand by for RCA" | DevOps Engineer | Stops active exploitation *without* downtime for legitimate users (internal tools still work) |
| **T+15–30 min** | **Evidence Preservation**<br>- Snapshot CloudWatch Logs for `/customers/view` endpoint (last 7 days)<br>- Export VPC Flow Logs for reporter's IP during incident window<br>- Freeze RDS read replica for forensic analysis (avoid production impact) | DevOps Engineer | Legal/regulatory requirement: evidence must be preserved before any system changes |
| **T+30–45 min** | **Stakeholder Notification**<br>- CTO: "Confirmed IDOR vulnerability; contained via WAF; investigation underway"<br>- Legal: "Assessing GDPR breach notification requirements based on investigation findings"<br>- Support Manager: "Brief agent on disclosure protocol; no client communication yet" | Security Lead | Prevents panic; aligns leadership before facts are complete |
| **T+45–60 min** | **Client Communication Prep**<br>- Draft holding statement: "We're investigating a potential access control issue reported internally. No evidence of external exploitation. Will update by [time]."<br>- **DO NOT** send yet (premature without investigation) | Comms Lead | Avoids unnecessary client alarm; prepares for worst-case scenario |

> **Critical Decision Point**: Why WAF instead of immediate patch?<br>
> - Patching destroys evidence of exploitation patterns<br>
> - WAF provides surgical containment (blocks parameter tampering) while preserving logs<br>
> - Industry standard: NIST SP 800-61r2 §3.3.2 — "Preserve evidence before remediation"

---

## 2. Investigation Checklist

### How Widespread Is This Vulnerability?
| Check | Tool/Method | Success Criteria |
|-------|-------------|------------------|
| Scan all API endpoints accepting object IDs (`customer_id`, `appointment_id`, etc.) | `grep -r "WHERE id =" src/` + manual review | Document every endpoint lacking tenant-scoped WHERE clause |
| Test mobile app endpoints with Burp Suite | Intercept request → modify `company_id` → observe response | Confirm vulnerability exists beyond web dashboard |
| Audit third-party integration webhooks | Review webhook handler code for tenant validation | Identify if calendar/email sync endpoints are vulnerable |
| Check admin/support console interfaces | Log in as support agent → attempt cross-tenant access | Verify if elevated-role tools have same flaw |

### What Data Was Potentially Exposed?
| Check | Tool/Method | Success Criteria |
|-------|-------------|------------------|
| Query CloudWatch Logs for `/customers/view` with anomalous `company_id` values | `fields @timestamp, @message \| filter company_id != user_company_id` | Identify all cross-tenant access attempts by reporter |
| Correlate with reporter's session token | Match `session_id` across logs to reconstruct full access path | Document exact records viewed (customer names, emails, notes) |
| Check S3 access logs for related file downloads | `aws s3api list-bucket-inventory-configurations --bucket clienthub-files` | Confirm no bulk data exfiltration occurred |
| Review RDS audit logs for SELECT queries with mismatched company_id | `SELECT * FROM pg_stat_statements WHERE query LIKE '%customers%'` | Verify database-level access patterns |

### Was It Exploited Before This Report?
| Check | Tool/Method | Success Criteria |
|-------|-------------|------------------|
| Search logs for sequential ID access patterns (7890→7891→7892) | CloudWatch Logs Insights: `stats count() by bin(5m) \| filter customer_id like /789[0-9]/` | Detect automated enumeration attempts |
| Identify anomalous user agents (scanners, Burp Suite) | `filter user_agent like /Burp\|sqlmap\|nuclei/` | Flag potential external exploitation attempts |
| Correlate with failed login attempts preceding access | Join auth logs with data access logs on IP/timestamp | Identify credential stuffing → IDOR exploitation chain |
| Check threat intel feeds for ClientHub domain mentions | Search HaveIBeenPwned, AlienVault OTX | Rule out prior breach disclosure |

> **Professional Note**: If investigation finds *no evidence* of prior exploitation AND data exposed was limited to reporter's test (single record), GDPR breach notification may not be required (ICO guidance: "no risk to rights/freedoms"). Legal must make final determination.

---

## 3. Root Cause Analysis

### Three Possible Technical Causes

| # | Cause | Evidence Required | Likelihood |
|---|-------|-------------------|------------|
| **1** | **Missing tenant validation in endpoint handler**<br>Developer wrote `SELECT * FROM customers WHERE id = ?` without `AND company_id = ?` | Code review of `/customers/view` handler | **High** — Most common in rapid feature development; matches symptom exactly |
| **2** | **Middleware bypass**<br>Endpoint excluded from centralized authZ middleware (e.g., route not covered by `app.use('/api/v1/', authZMiddleware)`) | Check route registration; middleware coverage report | Medium — Possible if endpoint added after middleware implementation |
| **3** | **Flawed authorization logic**<br>Validation exists but checks user role instead of tenant ownership (e.g., "is admin?" vs "owns this company?") | Review authZ logic; test with non-admin user | Low — Would cause broader access issues; reporter is support agent (not admin) |

### Most Likely Root Cause & Why
**Cause #1: Missing tenant validation in endpoint handler** is most probable because:
1. **Symptom specificity**: Only URL parameter tampering worked — indicates validation absent at data access layer
2. **Development pattern**: Early-stage startups often implement authZ per-endpoint rather than centralized middleware
3. **Feature velocity**: 18-month-old app likely added "view customer" endpoint during rapid iteration phase where security reviews were skipped
4. **Architectural evidence**: Part 2 analysis confirmed lack of tenant-bound JWTs + centralized middleware — making per-endpoint errors inevitable

> **Critical Distinction**: Root cause is *not* "developer error" — that's a symptom. True root cause: **Missing security control in SDLC** (no mandatory authZ review gate for data-access endpoints). Fix requires process change, not just code patch.

---

## 4. Fix Validation Protocol

After developer claims "fixed," perform these **negative tests** (proving what *should not work*):

### Test Matrix
| Test Case | Request | Expected Response | Tool |
|-----------|---------|-------------------|------|
| **Cross-tenant access (web)** | `GET /customers/view?customer_id=7892` (belongs to Company B) | `403 Forbidden` + security log entry | Browser + DevTools |
| **Cross-tenant access (API)** | `GET /api/v1/customers/7892` with valid JWT for Company A | `403 Forbidden` | curl + JWT |
| **Parameter tampering (body)** | `POST /appointments { "customer_id": 7892 }` (Company B record) | `403 Forbidden` | Postman |
| **Mobile app endpoint** | Intercept mobile request → change `company_id` → replay | `403 Forbidden` | Burp Suite |
| **Edge case: ID enumeration** | Script requesting `customer_id=7000` to `9000` | All non-owned IDs return `403` | Python script |
| **Logging verification** | Trigger blocked access attempt | CloudWatch alarm fires within 60s; log contains `TENANT_ISOLATION_VIOLATION` | AWS Console |

### Validation Success Criteria
✅ **All** negative tests return `403 Forbidden` (not `404` — which leaks existence)  
✅ Security logs capture *every* blocked attempt with: user ID, attempted resource, timestamp  
✅ No performance regression (>100ms latency increase) on legitimate requests  
✅ Code coverage report shows 100% of data-access routes execute authZ middleware  

### Final Sign-Off Checklist
- [ ] Security team validates all test cases pass
- [ ] Legal confirms investigation findings (no prior exploitation)
- [ ] CTO approves lifting temporary WAF rule
- [ ] Support agent who reported issue confirms fix works in staging
- [ ] Post-incident review scheduled within 72 hours (process improvement focus)

> **Why this matters**: Validation isn't "does the feature work?" — it's "does the *protection* work against adversarial input?" Hiring managers evaluate whether you test like an attacker.
