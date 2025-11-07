#!/usr/bin/env python3
"""Helper script to demonstrate policy hot-reload behavior.

Usage:
    PYTHONPATH=. python scripts/demo_policy_reload.py [policy_path]

Steps:
1. Run the script. It will print the current policy id list.
2. Edit the policy YAML (e.g., add/remove a rule description) and save.
3. Press Enter in the terminal to trigger reload; the script invalidates the cache
   and shows the updated policy metadata.
4. Type 'q' + Enter to exit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from app import policy


def _describe(policy_store: policy.PolicyStore, *, policy_id: str = "default") -> None:
    definition = policy.select_policy(policy_store, policy_id)
    print(f"\nPolicy '{definition.policy_id}' (tiers={definition.tiers})")
    print(f"- {len(definition.rules)} rules, {len(definition.allowlist)} allowlist entries")
    print("  Sample rules:")
    for rule in _take(definition.rules, 5):
        print(f"    • {rule.id} ({rule.type}/{rule.kind}) action={rule.action} risk_weight={rule.risk_weight}")


def _take(items: Iterable[policy.PolicyRule], limit: int) -> list[policy.PolicyRule]:
    bucket: list[policy.PolicyRule] = []
    for item in items:
        bucket.append(item)
        if len(bucket) >= limit:
            break
    return bucket


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Show policy cache reloads.")
    parser.add_argument(
        "policy_path",
        nargs="?",
        default="config/policy.yaml",
        type=Path,
        help="Path to policy YAML (default: config/policy.yaml)",
    )
    args = parser.parse_args()
    policy_path = args.policy_path.resolve()

    print(f"Loading policy from {policy_path}")
    store = policy.load_policy(policy_path)
    _describe(store)

    while True:
        user_input = input("\nEdit the file then press Enter to reload (or 'q' to quit): ").strip().lower()
        if user_input in {"q", "quit", "exit"}:
            break
        policy.invalidate_policy_cache(policy_path)
        store = policy.load_policy(policy_path)
        _describe(store)


if __name__ == "__main__":
    main()
