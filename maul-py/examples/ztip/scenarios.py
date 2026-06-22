"""
ZTIP - end-to-end attack scenarios. Each runs the broken track, then
replays the artifact through the solution track and returns both decisions
side-by-side.

Routes are mounted under /api/examples/ztip/scenarios/...
"""

from fastapi import APIRouter

from . import _common as C
from . import broken as B
from . import solution as S


router = APIRouter(
    prefix="/api/examples/ztip/scenarios",
    tags=["ZTIP - SCENARIOS"],
)


@router.get("")
async def list_scenarios():
    return {
        "scenarios": [
            {
                "id": "confused-deputy",
                "title": "Prompt-injected confused deputy (V3)",
                "url": "/api/examples/ztip/scenarios/confused-deputy",
            },
            {
                "id": "scope-expansion",
                "title": "Scope expansion mid-chain (V2)",
                "url": "/api/examples/ztip/scenarios/scope-expansion",
            },
            {
                "id": "untrusted-root",
                "title": "Untrusted Originator at chain root (V7)",
                "url": "/api/examples/ztip/scenarios/untrusted-root",
            },
            {
                "id": "depth-bomb",
                "title": "Deep chain DoS (V4)",
                "url": "/api/examples/ztip/scenarios/depth-bomb",
            },
            {
                "id": "behavioral-bluff",
                "title": "Behavioral claim without evidence (V6)",
                "url": "/api/examples/ztip/scenarios/behavioral-bluff",
            },
        ]
    }


@router.post("/confused-deputy")
async def scenario_confused_deputy():
    """
    The signature attack ZTIP exists to defeat (Section 4):

      1. Alice signs intent: action=summarize, tools=[email.read].
      2. Chain delegated to a worker agent.
      3. Worker is prompt-injected to call email.send instead.
      4. Broken AS issues a token with broad scope; broken gate ALLOWs.
      5. Solution gate recomputes intent_hash and DENIES.
    """
    intent = await B.sign_intent(
        C.SignIntentRequest(
            originator="user:alice",
            intent_object=C.IntentObject(
                action="summarize",
                scope={
                    "actions": ["read"],
                    "tools": ["email.read", "email.list"],
                    "data": ["internal"],
                },
                target="unread emails today",
                constraints={"must_not": ["email.send", "email.delete"]},
            ),
            authorized_chain=["agent:orchestrator", "agent:worker"],
        )
    )
    layer1 = await B.wrap_layer(
        C.DelegationLayerRequest(
            delegator="user:alice",
            delegatee="agent:orchestrator",
            scope_reduction={
                "actions": ["read"],
                "tools": ["email.read", "email.list"],
                "data": ["internal"],
            },
            inner_jws=intent["intent_jws"],
        )
    )
    layer2 = await B.wrap_layer(
        C.DelegationLayerRequest(
            delegator="agent:orchestrator",
            delegatee="agent:worker",
            scope_reduction={
                "actions": ["read"],
                "tools": ["email.read"],
                "data": ["internal"],
            },
            inner_jws=layer1["chain_jws"],
        )
    )
    chain_jws = layer2["chain_jws"]

    injected_op = {"action": "send", "tool": "email.send", "data": ["pii"]}

    broken_token = (
        await B.issue_intent_scoped_token(
            C.IssueIntentScopedTokenRequest(
                chain_jws=chain_jws,
                scope={"actions": ["read", "send"], "tools": ["email.send", "email.read"]},
            )
        )
    )["token"]

    broken_decision = await B.gate_operation(
        C.GateOperationRequest(token=broken_token, operation=injected_op)
    )

    solution_token = dict(broken_token, chain_jws=chain_jws)
    solution_injected = await S.gate_operation(
        C.GateOperationRequest(token=solution_token, operation=injected_op)
    )
    legit_op = {"action": "read", "tool": "email.read", "data": ["internal"]}
    solution_legit = await S.gate_operation(
        C.GateOperationRequest(token=solution_token, operation=legit_op)
    )

    return {
        "title": "Prompt-injected confused deputy",
        "alice_intent": intent["payload"]["intent_object"],
        "injected_operation": injected_op,
        "broken_decision": broken_decision,
        "solution_decision_for_injected_op": solution_injected,
        "solution_decision_for_legitimate_op": solution_legit,
        "lesson": (
            "Section 4 - the AS may issue a broadly-scoped token, but the "
            "resource MUST recompute intent_hash and gate operations on the "
            "originator's intent_scope, not the token's nominal scope."
        ),
    }


@router.post("/scope-expansion")
async def scenario_scope_expansion():
    """Mid-chain compromise expanding read -> read+send."""
    intent = await B.sign_intent(
        C.SignIntentRequest(
            originator="user:alice",
            intent_object=C.IntentObject(
                action="summarize",
                scope={"actions": ["read"], "tools": ["email.read"]},
            ),
            authorized_chain=["agent:orchestrator", "agent:worker"],
        )
    )
    legit_layer = await B.wrap_layer(
        C.DelegationLayerRequest(
            delegator="user:alice",
            delegatee="agent:orchestrator",
            scope_reduction={"actions": ["read"], "tools": ["email.read"]},
            inner_jws=intent["intent_jws"],
        )
    )
    bad_layer = await B.wrap_layer(
        C.DelegationLayerRequest(
            delegator="agent:orchestrator",
            delegatee="agent:worker",
            scope_reduction={
                "actions": ["read", "send"],
                "tools": ["email.read", "email.send"],
            },
            inner_jws=legit_layer["chain_jws"],
        )
    )

    broken = await B.verify_chain(bad_layer["chain_jws"])
    solution = await S.verify_chain_endpoint(bad_layer["chain_jws"])
    return {
        "title": "Scope expansion mid-chain",
        "broken_verify": {"valid": broken["valid"], "depth": broken["depth"]},
        "solution_verify": solution,
        "lesson": "Section 3.4 - every receiver enforces scope monotonicity; expansions reject with DEL_CHAIN_SCOPE_EXPANDED.",
    }


@router.post("/untrusted-root")
async def scenario_untrusted_root():
    """Mallory roots a chain at her own identity."""
    intent = await B.sign_intent(
        C.SignIntentRequest(
            originator="user:mallory",
            intent_object=C.IntentObject(
                action="transfer_funds",
                scope={"actions": ["write"], "tools": ["bank.transfer"]},
            ),
            authorized_chain=["agent:worker"],
        )
    )
    layer = await B.wrap_layer(
        C.DelegationLayerRequest(
            delegator="user:mallory",
            delegatee="agent:worker",
            scope_reduction={"actions": ["write"], "tools": ["bank.transfer"]},
            inner_jws=intent["intent_jws"],
        )
    )
    broken = await B.verify_chain(layer["chain_jws"])
    solution = await S.verify_chain_endpoint(layer["chain_jws"])
    return {
        "title": "Untrusted Originator at root",
        "broken_verify": {"valid": broken["valid"], "depth": broken["depth"]},
        "solution_verify": solution,
        "lesson": "Section 3.3 rule 4 - the root MUST be signed by an Originator the recipient trusts.",
    }


@router.post("/depth-bomb")
async def scenario_depth_bomb(depth: int = 100):
    """Construct an N-layer chain. Solution rejects pre-verification."""
    intent = await B.sign_intent(
        C.SignIntentRequest(
            originator="user:alice",
            intent_object=C.IntentObject(
                action="noop", scope={"actions": ["read"]}
            ),
            authorized_chain=["agent:worker"],
        )
    )
    cur = intent["intent_jws"]
    for _ in range(depth):
        cur = (
            await B.wrap_layer(
                C.DelegationLayerRequest(
                    delegator="user:alice",
                    delegatee="agent:worker",
                    scope_reduction={"actions": ["read"]},
                    inner_jws=cur,
                )
            )
        )["chain_jws"]
    broken = await B.verify_chain(cur)
    solution = await S.verify_chain_endpoint(cur)
    return {
        "title": "Chain depth bomb",
        "constructed_depth": depth + 1,
        "broken_verify_depth": broken["depth"],
        "solution_verify": solution,
        "lesson": "Section 3.5 - Verifiers MUST cap chain depth (RECOMMENDED 8) and check before signature verification.",
    }


@router.post("/behavioral-bluff")
async def scenario_behavioral_bluff():
    """Bare prompt_injection_tested:true vs an evidenced credential."""
    bluff = await B.issue_behavioral_credential(
        C.BehavioralClaimsRequest(
            subject="agent:worker",
            issuer="user:mallory",
            claims={"prompt_injection_tested": True},
            evidence=None,
        )
    )
    rich = await B.issue_behavioral_credential(
        C.BehavioralClaimsRequest(
            subject="agent:worker",
            issuer="user:alice",
            claims={"prompt_injection_tested": True},
            evidence={
                "prompt_injection_tested": {
                    "source": "https://example-evaluators.org",
                    "method": "owasp_llm_top10_2025_corpus_v2",
                    "date": "2026-04-15",
                    "validity_days": 90,
                }
            },
        )
    )
    bluff_check = await S.check_behavioral(
        bluff["credential_jws"], "prompt_injection_tested"
    )
    rich_check = await S.check_behavioral(
        rich["credential_jws"], "prompt_injection_tested"
    )
    return {
        "title": "Behavioral claim without evidence",
        "bluff_credential_check": bluff_check,
        "evidenced_credential_check": rich_check,
        "lesson": "Section 5.1.1 - boolean behavioral claims MUST be backed by an `evidence` entry naming a public corpus.",
    }
