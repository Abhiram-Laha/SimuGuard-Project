# SimuGuard AI — Risk Engine Mathematical Verification (Phase 4)

This document presents the independent mathematical verification of `simuguard/engine/risk_engine.py` against the required scoring formulas, boundaries, deduplication logic, and verdict precedence state machine.

---

## 1. Mathematical Formula Specification

The composite risk score $R \in [0, 100]$ is calculated as:

$$\text{Base Score} = \sum_{g \in \text{DeduplicatedGaps}} W(\text{severity}_g) \times M(\text{highest\_criticality})$$

$$\beta = \min\left(2.0, \; 1.0 + 0.05 \times N_{\text{direct}} + 0.02 \times N_{\text{cascading}}\right)$$

$$R = \min\left(100, \; \max\left(0, \; \text{round}\left(\text{Base Score} \times \beta\right)\right)\right)$$

### Parameter Specifications

1. **Severity Weights $W(\text{severity})$:**
   - $\text{CRITICAL} = 40.0$
   - $\text{HIGH} = 25.0$
   - $\text{MEDIUM} = 10.0$
   - $\text{LOW} = 3.0$
2. **Asset Criticality Multipliers $M(\text{criticality})$:**
   - $\text{CRITICAL} = 1.5$ (e.g. S3 CUI Vault, RDS Payment DB, Perimeter Firewalls)
   - $\text{HIGH} = 1.2$ (e.g. Internal Firewalls, Production VPC, EKS Production Cluster)
   - $\text{MEDIUM} = 1.0$ (e.g. Corporate User Subnets, SIEM Forwarders)
   - $\text{LOW} = 0.8$ (e.g. Development Sandbox, Non-sensitive Test Buckets)
3. **Blast Radius Multiplier $\beta$:**
   - Evaluates direct impacts ($N_{\text{direct}}$) and cascading transitive impacts ($N_{\text{cascading}}$).
   - Base value is $1.0$ (no amplification).
   - Strictly capped at $2.0$.
4. **Score Bounds:**
   - Strictly constrained: $0 \le R \le 100$.

---

## 2. Independent Verification Results

### Test 1: Finding Deduplication
- **Method:** Evaluated duplicate findings having identical `(rule_id, gap_title)`.
- **Expected:** Only unique findings contribute to the Base Score.
- **Actual Result:** Verified. Deduplication by `(rule_id, gap_title)` suppresses redundant findings from contributing duplicate weight.

### Test 2: Asset Criticality Selection
- **Method:** Evaluated a heterogeneous set of affected assets across LOW, HIGH, and CRITICAL classifications.
- **Expected:** Criticality multiplier reflects the highest criticality among affected assets in the blast radius ($M = 1.5$).
- **Actual Result:** Verified. `_determine_highest_criticality` selects CRITICAL ($1.5$), prioritizing the protection of high-value assets.

### Test 3: Blast Radius Multiplier Cap
- **Method:** Evaluated 30 direct impacts ($30 \times 0.05 = 1.5 \implies 1.0 + 1.5 = 2.5$).
- **Expected:** Multiplier is capped at $2.0$.
- **Actual Result:** Verified. $\beta = 2.0$.

### Test 4: Boundary Conditions ($0$ and $100$)
- **Zero Findings:** Base Score $= 0.0$, $\beta = 1.0 \implies R = 0$. Verdict: `ALLOW`.
- **Maximum Risk:** High findings on critical assets with wide blast radius cap at $R = 100$. Verdict: `BLOCK_DEPLOYMENT`.

---

## 3. Verdict Precedence State Machine Verification

The verdict precedence rules ensure that security severity always overrides numerical scores:

| Case | Scenario | Numerical Score | Finding Severity | UNKNOWN Present | Resulting Verdict | Precedence Rule Enforced |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | Single CRITICAL gap | 40 (Low) | CRITICAL | No | **BLOCK_DEPLOYMENT** | Precedence 1: Any CRITICAL finding forces BLOCK_DEPLOYMENT. |
| **B** | Composite score $\ge 70$ | 75 | HIGH | No | **BLOCK_DEPLOYMENT** | Precedence 1: Score $\ge 70$ forces BLOCK_DEPLOYMENT. |
| **C** | Single HIGH gap | 25 (Low) | HIGH | No | **WARN_MANUAL_REVIEW** | Precedence 2: Any HIGH finding forces WARN_MANUAL_REVIEW. |
| **D** | Unmapped Resource | 3 (Low) | LOW | **Yes** | **WARN_MANUAL_REVIEW** | Precedence 2: UNKNOWN impact forces WARN_MANUAL_REVIEW. |
| **E** | Score in $40 - 69$ | 52 | MEDIUM | No | **WARN_MANUAL_REVIEW** | Precedence 2: Elevated score forces WARN_MANUAL_REVIEW. |
| **F** | Fully Compliant | 3 (Low) | LOW | No | **ALLOW** | Precedence 3: Score $< 40$, 0 HIGH/CRITICAL, 0 UNKNOWN. |

**Audit Conclusion:**
The risk engine operates deterministically. Numerical scores never override more severe security findings, and unmapped resources can never result in an `ALLOW` verdict.
