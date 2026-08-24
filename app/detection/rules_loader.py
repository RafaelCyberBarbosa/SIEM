import os
import yaml
from sqlalchemy.orm import Session

from app.models import Rule

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "default_rules.yaml")


def load_default_rules_into_db(db: Session):
    """Seeds built-in rules from default_rules.yaml. Only inserts rules that
    don't already exist (by rule_key), so user edits via the UI persist."""
    with open(DEFAULT_RULES_PATH, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f) or []

    existing_keys = {r.rule_key for r in db.query(Rule.rule_key).all()}
    created = 0
    for r in rules:
        if r["rule_key"] in existing_keys:
            continue
        rule = Rule(
            rule_key=r["rule_key"],
            name=r["name"],
            description=r.get("description", ""),
            type=r["type"],
            severity=r.get("severity", "medium"),
            mitre=r.get("mitre", ""),
            enabled=True,
            definition=r.get("definition", {}),
            is_builtin=True,
        )
        db.add(rule)
        created += 1
    if created:
        db.commit()
    return created
