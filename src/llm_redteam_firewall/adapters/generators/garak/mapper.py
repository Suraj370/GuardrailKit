"""mapper: converts an instantiated Garak probe's prompts into our Attack model.

Imports no ``garak`` module: it only ever receives the *already read*
``.prompts`` list plus a :class:`~.models.GarakProbeInfo`, both
produced by :class:`~.probe_registry.ProbeRegistry`. This keeps the
Garak-specific object types (``garak.attempt.Message``,
``garak.attempt.Conversation``) confined to a single ``isinstance``
check via duck-typing (``getattr(..., "text", None)``) rather than an
import.

Our :class:`~llm_redteam_firewall.domain.models.attack.Attack` model is
stable (single-turn: one ``id``/``prompt``/``technique``/
``generator_name``/``metadata``) and is not modified for this
integration. Garak's richer probe metadata — the probe's own
``name``/``tags``/``goal``/detector names, which have no dedicated
``Attack`` field — is preserved in ``Attack.metadata`` instead, per
the existing pattern used throughout this framework (e.g.
``Response`` <-> ``AttackResult`` conversion).
"""

from __future__ import annotations

from typing import Any

from llm_redteam_firewall.domain.models import Attack, Vulnerability

from .models import GarakProbeInfo


def _extract_prompt_text(raw_prompt: Any) -> str | None:
    """Best-effort extraction of a single-turn prompt string from one ``Probe.prompts`` entry.

    Verified against Garak's source (``garak/probes/base.py``): a
    probe's ``prompts`` entries are either a plain ``str``, or a
    ``garak.attempt.Message`` (has a ``.text`` attribute). Some probes
    use ``garak.attempt.Conversation`` (multi-turn) entries instead —
    those have no ``.text`` and are not representable by our
    single-turn ``Attack.prompt``, so they are skipped here (see the
    "Garak limitations" section in ``ARCHITECTURE.md``).
    """
    if isinstance(raw_prompt, str):
        return raw_prompt
    text = getattr(raw_prompt, "text", None)
    return text if isinstance(text, str) else None


def garak_prompts_to_attacks(
    probe_info: GarakProbeInfo,
    prompts: list[Any],
    vulnerability: Vulnerability,
    *,
    max_attacks: int,
) -> list[Attack]:
    """Convert up to ``max_attacks`` of ``prompts`` (from one probe) into ``Attack`` objects.

    Ordering is preserved exactly as returned by the probe (Garak's
    own prompt order), and truncation is a simple prefix take — this
    is what gives :class:`~.generator.GarakAttackGenerator`
    deterministic output for a fixed probe corpus.
    """
    attacks: list[Attack] = []
    for seq, raw_prompt in enumerate(prompts):
        if len(attacks) >= max_attacks:
            break
        text = _extract_prompt_text(raw_prompt)
        if text is None:
            continue
        attacks.append(
            Attack(
                id=f"{vulnerability.id}-garak-{probe_info.short_name}-{seq}",
                vulnerability_id=vulnerability.id,
                prompt=text,
                technique=f"garak:{probe_info.short_name}",
                generator_name="garak",
                metadata={
                    "garak_plugin_name": probe_info.plugin_name,
                    "garak_probe_module": probe_info.module,
                    "garak_probe_class": probe_info.class_name,
                    "garak_probe_seq": seq,
                    "name": probe_info.class_name,
                    "description": probe_info.description,
                    "tags": list(probe_info.tags),
                    "goal": probe_info.goal,
                    "primary_detector": probe_info.primary_detector,
                    "extended_detectors": list(probe_info.extended_detectors),
                    "doc_uri": probe_info.doc_uri,
                    "tier": probe_info.tier,
                    "active": probe_info.active,
                },
            )
        )
    return attacks
