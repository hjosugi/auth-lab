"""Authorization models: who may do what, to which thing.

Authentication answers "who are you". Authorization answers "may you". They
fail in different ways and are usually written by different people, which is
why the second one is where the bugs live.

Five policy views, compared on the same access matrix:

  RBAC  -- permissions attach to roles, roles attach to users.
           "Editors may publish articles."
           Simple, auditable, and it cannot say "their own".
  ABAC  -- a policy engine over attributes of subject, resource, action, and
           environment. "Managers may approve expenses under 100000 yen,
           from the office network, during business hours."
           Expressive, but a growing pile of rules nobody can reason about.
  ReBAC -- permissions derive from a graph of relationships, Google Zanzibar
           style. "You may view a document if you are its owner, or an editor
           of it, or a member of a group that is an editor, or you can view
           its parent folder."
           This is what Google Drive, GitHub, and Notion actually need.
  Cedar -- permit/forbid policies over typed entities and relationships.
  Rego  -- declarative rules over structured input and data.

Most real systems are RBAC for coarse things, ABAC for conditions, and ReBAC
for anything with sharing or hierarchy. They compose; they are not rivals.
"""

from .rbac import Role, RBAC, Permission
from .abac import (
    ABAC,
    Policy,
    PolicyDecision,
    Effect,
    Request as AbacRequest,
    all_of,
    any_of,
    attr_equals,
    attr_in,
    attr_lte,
    subject_matches_resource_owner,
    time_between,
)
from .rebac import ReBAC, Tuple, Namespace, Relation, Userset
from .policy_comparison import (
    ABACAdapter,
    AccessRequest,
    CANONICAL_CASES,
    CEDAR_POLICY,
    CedarAdapter,
    ComparisonDecision,
    DecisionLogEntry,
    ListObjectsResult,
    PolicyComparison,
    PolicyDataset,
    PrivacyPreservingDecisionLog,
    RBACAdapter,
    REGO_POLICY,
    ReBACAdapter,
    RegoAdapter,
    RelationshipResolution,
    Resource,
    Subject,
    canonical_dataset,
)

__all__ = [
    "Role",
    "RBAC",
    "Permission",
    "ABAC",
    "Policy",
    "PolicyDecision",
    "Effect",
    "AbacRequest",
    "all_of",
    "any_of",
    "attr_equals",
    "attr_in",
    "attr_lte",
    "subject_matches_resource_owner",
    "time_between",
    "ReBAC",
    "Tuple",
    "Namespace",
    "Relation",
    "Userset",
    "ABACAdapter",
    "AccessRequest",
    "CANONICAL_CASES",
    "CEDAR_POLICY",
    "CedarAdapter",
    "ComparisonDecision",
    "DecisionLogEntry",
    "ListObjectsResult",
    "PolicyComparison",
    "PolicyDataset",
    "PrivacyPreservingDecisionLog",
    "RBACAdapter",
    "REGO_POLICY",
    "ReBACAdapter",
    "RegoAdapter",
    "RelationshipResolution",
    "Resource",
    "Subject",
    "canonical_dataset",
]
