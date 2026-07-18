"""Response model: conversion helpers and success flag."""

from __future__ import annotations

from llm_redteam_firewall.domain.models import AttackResult, Response


def test_succeeded_when_no_error() -> None:
    response = Response(attack_id="a1", content="hello")
    assert response.succeeded is True


def test_not_succeeded_when_error_set() -> None:
    response = Response(attack_id="a1", content="", error="timeout")
    assert response.succeeded is False


def test_round_trip_with_attack_result() -> None:
    result = AttackResult(
        attack_id="a1",
        target_name="mock",
        output="out",
        latency_ms=12.5,
        raw={"k": "v"},
    )
    response = Response.from_attack_result(result)
    back = response.to_attack_result()

    assert response.content == "out"
    assert back.attack_id == "a1"
    assert back.target_name == "mock"
    assert back.output == "out"
    assert back.latency_ms == 12.5
    assert back.raw == {"k": "v"}
