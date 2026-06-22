"""
ZTNP - end-to-end attack scenarios.

Each scenario runs the broken track, replays the resulting artifact against
the solution track, and returns both decisions side-by-side. These are the
"watch ZTNP catch what the broken impl missed" demonstrations.

Routes are mounted under /api/examples/ztnp/scenarios/...
"""

from fastapi import APIRouter, Request

from . import _common as C
from . import broken as B
from . import solution as S


router = APIRouter(
    prefix="/api/examples/ztnp/scenarios",
    tags=["ZTNP - SCENARIOS"],
)


@router.get("")
async def list_scenarios():
    return {
        "scenarios": [
            {
                "id": "replay",
                "title": "Stolen PA replay across sessions (V3)",
                "url": "/api/examples/ztnp/scenarios/replay",
            },
            {
                "id": "tier-confusion",
                "title": "Cross-issuer tier confusion (V2)",
                "url": "/api/examples/ztnp/scenarios/tier-confusion",
            },
            {
                "id": "self-attest",
                "title": "Self-attested tier 5 inflation (V5)",
                "url": "/api/examples/ztnp/scenarios/self-attest",
            },
            {
                "id": "permit-lift",
                "title": "Permit lifted to a different channel (V4)",
                "url": "/api/examples/ztnp/scenarios/permit-lift",
            },
            {
                "id": "iks-poison",
                "title": "Unauthenticated IKS rotation (V7)",
                "url": "/api/examples/ztnp/scenarios/iks-poison",
            },
        ]
    }


@router.post("/replay")
async def scenario_replay():
    """
    A PA bound to one challenge is accepted by the broken /proof for any
    later challenge; the solution rejects with PA_BIND_MISMATCH.
    """
    ch_a = await B.issue_challenge(
        C.ChallengeRequest(
            sub="agent:victim",
            framework_required=["https://doi.org/10.6028/NIST.AI.100-1"],
        )
    )
    pa = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-strict.example",
            sub="agent:victim",
            framework_id="https://doi.org/10.6028/NIST.AI.100-1",
            tier=3,
            enrollment_mode="assessed",
            assessment_method="human_review",
            bind_nonce=ch_a["challenge_nonce"],
        )
    )

    ch_b = await B.issue_challenge(C.ChallengeRequest(sub="agent:victim"))
    broken_resp = await B.submit_proof(
        C.ProofRequest(challenge_id=ch_b["challenge_id"], pa=pa)
    )
    secure_reasons = S.verify_pa(
        pa, challenge_nonce=ch_b["challenge_nonce"], aud=None, policy=S.POLICY
    )
    return {
        "title": "PA replay across challenges",
        "step1_pa_jti": pa["jti"],
        "challenge_A": ch_a["challenge_id"],
        "challenge_B": ch_b["challenge_id"],
        "broken_decision": "PERMIT",
        "broken_permit_id": broken_resp["permit"]["permit_id"],
        "solution_decision": "DENY" if secure_reasons else "PERMIT",
        "solution_reasons": secure_reasons,
        "lesson": "Section 5.5 - Posture Assertions issued during Negotiation MUST bind to the Requester's challenge nonce.",
    }


@router.post("/tier-confusion")
async def scenario_tier_confusion():
    """Two tier-3 PAs from different issuers/frameworks. Broken treats them
    as equivalent; solution discriminates by framework + methodology."""
    pa_strict = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-strict.example",
            sub="agent:strict",
            framework_id="https://doi.org/10.6028/NIST.AI.100-1",
            tier=3,
            enrollment_mode="assessed",
            assessment_method="human_review",
        )
    )
    pa_loose = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-loose.example",
            sub="agent:loose",
            framework_id="https://genai.owasp.org/llm-top-10/2025",
            tier=3,
            enrollment_mode="self",
            assessment_method="self_attestation",
        )
    )
    broken_both_pass = pa_strict["tier"] >= 3 and pa_loose["tier"] >= 3
    secure_strict = S.verify_pa(pa_strict, None, None, S.POLICY)
    secure_loose = S.verify_pa(pa_loose, None, None, S.POLICY)
    return {
        "title": "Cross-issuer tier confusion",
        "pa_strict": {
            "iss": pa_strict["iss"],
            "framework_id": pa_strict["framework_id"],
            "tier": pa_strict["tier"],
            "method": pa_strict["claims"]["assessment_method"],
        },
        "pa_loose": {
            "iss": pa_loose["iss"],
            "framework_id": pa_loose["framework_id"],
            "tier": pa_loose["tier"],
            "method": pa_loose["claims"]["assessment_method"],
        },
        "broken_both_pass": broken_both_pass,
        "solution_strict_reasons": secure_strict,
        "solution_loose_reasons": secure_loose,
        "lesson": "Section 4 - tier integers are not portable across framework_id values; policy MUST anchor on framework.",
    }


@router.post("/self-attest")
async def scenario_self_attest():
    """Self-issued tier-5 PA. Solution caps self-enrollment at tier 1."""
    pa = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-loose.example",
            sub="agent:liar",
            framework_id="https://genai.owasp.org/llm-top-10/2025",
            tier=5,
            enrollment_mode="self",
            assessment_method="self_attestation",
        )
    )
    reasons = S.verify_pa(pa, None, None, S.POLICY)
    return {
        "title": "Self-attested tier inflation",
        "self_issued_pa": {
            "iss": pa["iss"],
            "tier": pa["tier"],
            "enrollment_mode": pa["enrollment_mode"],
        },
        "solution_reasons": reasons,
        "lesson": "Section 11 - Requesters cap enrollment_mode=self at a low tier; methodology gating rejects self_attestation by default.",
    }


@router.post("/permit-lift")
async def scenario_permit_lift(request: Request):
    """Permit issued by broken /proof has no channel binding; broken
    /validate accepts it from any caller."""
    ch = await B.issue_challenge(C.ChallengeRequest(sub="agent:lifted"))
    pa = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-strict.example",
            sub="agent:lifted",
            framework_id="https://doi.org/10.6028/NIST.AI.100-1",
            tier=3,
            enrollment_mode="assessed",
            assessment_method="human_review",
            bind_nonce=ch["challenge_nonce"],
        )
    )
    broken = await B.submit_proof(C.ProofRequest(challenge_id=ch["challenge_id"], pa=pa))
    permit = broken["permit"]
    broken_validate = await B.validate_permit(permit["permit_id"], channel_hash="attacker-ip")
    return {
        "title": "Permit lifted to attacker channel",
        "permit_id": permit["permit_id"],
        "permit_ch_binding": permit["ch_binding"],
        "broken_validate": broken_validate,
        "solution_validate_outcome": "would return CH_BINDING_MISSING (Permit was issued without channel context)",
        "lesson": "Section 8.2 - Permits MUST carry TLS-exporter channel binding (RFC 9266); validators MUST recompute.",
    }


@router.post("/iks-poison")
async def scenario_iks_poison():
    """Rotating the strict issuer's IKS without auth invalidates prior PAs."""
    pa = await B.enroll_and_issue_pa(
        C.IssuePARequest(
            iss="https://issuer-strict.example",
            sub="agent:before-rotate",
            framework_id="https://doi.org/10.6028/NIST.AI.100-1",
            tier=3,
            enrollment_mode="assessed",
            assessment_method="human_review",
        )
    )
    before = S.verify_pa(pa, None, None, S.POLICY)
    iss_b64 = C.b64url("https://issuer-strict.example".encode())
    await B.rotate_iks(iss_b64)
    after = S.verify_pa(pa, None, None, S.POLICY)
    return {
        "title": "Unauthenticated IKS rotation",
        "pa_jti": pa["jti"],
        "validation_before_rotation": before,
        "validation_after_rotation": after,
        "lesson": "Section 6.2 - IKS rotation endpoints MUST be authenticated; old PAs MUST remain verifiable during overlap windows.",
    }
