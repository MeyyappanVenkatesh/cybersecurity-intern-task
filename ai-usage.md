# AI Usage Documentation

## How AI Was Used
I used an AI assistant as a **senior technical mentor and architecture reviewer** to:
1. Structure the 4-hour project timeline with detailed learning guide.
2. Challenge assumptions and identify blind spots in threat modeling
3. Refine technical writing.

AI was **not** used to generate raw technical content, risk judgments, or breach examples. All security reasoning, likelihood calibrations, AWS implementation details, and incident response steps reflect my independent analysis.

## Key Prompts & Critical Evaluation

### Prompt 1: Structural Guidance
> *"Act as my senior security architect. Review my threat model draft for ClientHub and identify where I'm making beginner assumptions about attack surfaces."*

**AI Output**: Suggested focusing on API authorization layer over SQLi; explained multi-tenant isolation as existential risk.

**My Evaluation & Modifications**:
- ✅ **Accepted**: Multi-tenant isolation as #1 risk — aligned with OWASP API Security Top 10 and SaaS breach patterns I researched independently.
- ✅ **Modified**: AI initially dismissed SQLi too absolutely ("effectively solved"). I refined to *"lower likelihood relative to authorization flaws"* after reviewing Veracode 2024 report showing 12% of apps still vulnerable.
- ✅ **Rejected**: AI suggested "nation-state actors unlikely" without nuance. I added explicit threat actor calibration (opportunistic vs. targeted vs. APT) to show deliberate scope boundaries.

### Prompt 2: Technical Precision Refinement
> *"Review my HubSpot breach analogy. Is my technical description accurate or overstated?"*

**AI Output**: Flagged overconfident phrasing ("manipulate object identifiers") that didn't match HubSpot's OAuth token misuse mechanics.

**My Evaluation & Modifications**:
- ✅ **Accepted**: Revised to *"attackers abused API authorization flaws"* — accurate without overclaiming mechanics.
- ✅ **Added Original Analysis**: Researched HubSpot's March 2022 advisory independently to confirm OAuth/third-party app vector; added this detail to show I verified the source.

### Prompt 3: Trade-off Completeness
> *"What's missing from my JWT tenant-binding trade-off analysis?"*

**AI Output**: Suggested mentioning token staleness if user-company relationships change.

**My Evaluation & Modifications**:
- ✅ **Accepted & Expanded**: Added *"requires token revocation or short TTLs"* but also evaluated ClientHub's user model (single-company permanent assignment) to justify low operational impact — showing business-context judgment AI didn't provide.

## Original Analysis Beyond AI Outputs

| Component | My Independent Contribution |
|-----------|-----------------------------|
| **Likelihood Calibration** | Researched Verizon DBIR 2024 to justify "Medium-High" for support console (22% insider involvement stat) — AI suggested generic "Medium" |
| **Incident Response Timing** | Designed 60-minute action sequence based on NIST SP 800-61r2 evidence preservation requirements — AI suggested generic "contain then investigate" |
| **Fix Validation Matrix** | Created negative testing protocol distinguishing `403` (correct) vs `404` (information leak) — critical nuance AI missed |
| **GDPR Notification Logic** | Researched ICO guidance on "no risk to rights/freedoms" exemption — applied to investigation findings |

## Why This Approach Demonstrates Independent Thinking
AI served as a **critical reviewer**, not a content generator. Every technical claim was:
1. Researched independently (OWASP, Verizon DBIR, HubSpot advisory)
2. Evaluated against ClientHub's specific constraints (200 clients, AWS stack, 18-month age)
3. Modified when AI suggestions lacked nuance (SQLi dismissal, token staleness)
4. Expanded with business context AI cannot provide (GDPR fines vs. engineering cost trade-offs)

This mirrors real-world security practice: leveraging tools for efficiency while maintaining ownership of risk judgments.
