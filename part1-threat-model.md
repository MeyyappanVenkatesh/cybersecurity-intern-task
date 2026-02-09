# Part 1: Threat Model & Attack Surface Analysis

## Methodology
Threats prioritized using **business impact** (multi-tenant data breach = existential risk) and **realistic likelihood** calibrated to attacker effort/reward for a 200-client SaaS platform. Likelihood considers:
- Opportunistic attackers (script kiddies, automated scanners)
- Targeted small-business attackers (competitors, disgruntled ex-employees)
- *Not* nation-states (low ROI for this platform size)

Note: Common risks like SQL injection and XSS are *lower likelihood relative to authorization flaws* in modern stacks (parameterized queries are default in ORMs like Prisma/Sequelize), but not impossible. They also typically compromise *single* accounts rather than enabling cross-tenant data breaches — the CTO's explicit concern for enterprise onboarding.

## Critical Attack Surfaces

### 1. API Authorization Layer (Multi-Tenant Isolation Failure)
**Threat**: Attacker manipulates object identifiers (`customer_id`, `company_id`) in API requests to access/modify data belonging to other tenants without any prior account compromise.
**Impact**: Catastrophic — complete loss of client trust, GDPR/CCPA violations (€20M+ fines), immediate churn of all 200 clients.
**Likelihood**: High — IDOR is #1 OWASP API Security risk (2023); trivial to exploit with browser dev tools; no specialized skills or credentials required.

### 2. Session Management & Token Validation
**Threat**: JWT/OAuth access tokens lack embedded tenant context. Attacker authenticates to their tenant, then reuses token against another tenant's endpoints.
**Impact**: Severe — full account takeover across multiple tenants without credential compromise.
**Likelihood**: Medium — requires understanding of token structure; but common in early-stage SaaS apps that add multi-tenancy after MVP.

### 3. S3 Direct Object Access
**Threat**: Application generates presigned URLs or public S3 paths without tenant-scoped keys (e.g., `s3://clienthub-files/customer_789.pdf` vs `s3://clienthub-files/company_1234/customer_789.pdf`). Attacker enumerates object keys.
**Impact**: Severe — bulk exfiltration of PII/payment history without API interaction.
**Likelihood**: Medium — requires S3 bucket enumeration; but common misconfiguration in startups using S3 for rapid prototyping.

### 4. Support/Admin Console Interfaces
**Threat**: Internal tools for support agents lack strict access logging or tenant-switching controls. Agent (or compromised agent account) accesses arbitrary tenant data.
**Impact**: Critical — insider threat or compromised agent account leads to targeted data theft; reputational damage from "trusted employee" breach.
**Likelihood**: Medium-High — support workflows often prioritize convenience over security; 2023 Verizon DBIR shows 22% of breaches involve internal actors. *However, this requires either insider access or prior compromise of an agent account — a higher barrier than unauthenticated IDOR.*

### 5. Third-Party Integration Callbacks
**Threat**: Webhook endpoints for calendar/email sync accept payloads without validating tenant ownership of referenced resources.
**Impact**: Moderate-Severe — attacker injects malicious events into victim tenant's calendar/communications.
**Likelihood**: Low-Medium — requires compromising third-party service first; but supply chain attacks rising (2023 SolarWinds-style incidents up 650%).

## Top 3 Prioritized Risks

| Rank | Risk | Impact | Likelihood | Combined Risk |
|------|------|--------|------------|---------------|
| 1 | API Authorization Layer (IDOR) | Catastrophic | High | Critical |
| 2 | Support/Admin Console Access | Critical | Medium-High | High |
| 3 | S3 Direct Object Access | Severe | Medium | High |

## Prioritization Logic

1. **API Authorization Failure (#1)** — Highest priority because:
   - Requires **zero prior access**: attacker needs only a free trial account (or none at all for unauthenticated endpoints) to exploit
   - Directly enables the Part 3 scenario (URL parameter tampering) — proving this is an active, unmitigated risk
   - Impact is existential: enterprise clients mandate proven multi-tenant isolation before onboarding
   - Industry evidence: 48% of SaaS breaches in 2023 involved broken access control (Veracode State of Software Security 2024)

2. **Support Console Access (#2)** — Second priority because:
   - Human surfaces are consistently weakest link (Verizon DBIR 2024)
   - Support agents have elevated access by design — failure here bypasses all perimeter controls
   - *However, it ranks below IDOR because exploitation requires either insider access or prior compromise of an agent account — a meaningful barrier compared to IDOR's zero-access requirement*

3. **S3 Misconfiguration (#3)** — Third priority because:
   - Impact is severe but typically *detectable* via AWS CloudTrail/S3 access logs
   - Requires attacker to discover bucket naming convention (slightly higher barrier than IDOR)
   - However, remains critical due to AWS's shared responsibility model — ClientHub owns bucket policy configuration
