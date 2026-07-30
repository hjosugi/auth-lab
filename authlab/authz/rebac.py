"""ReBAC: relationship-based access control, Google Zanzibar style.

Zanzibar is the system behind Google Drive, YouTube, and Cloud IAM, and its
2019 paper is the reference for this whole category (OpenFGA, SpiceDB, Ory
Keto, Auth0 FGA are all descendants). The core idea is small enough to fit on
a napkin:

Everything is a **relation tuple**:

    object#relation@user            document:budget#viewer@user:alice
                                    document:budget#editor@group:finance#member
                                    document:budget#parent@folder:2024

The `user` half can be a concrete subject OR another *userset* -- "everyone
who is a member of group:finance". That one bit of indirection is what makes
groups, nested groups, and teams-of-teams fall out for free.

Then each relation in a namespace has a **userset rewrite** saying how it is
computed:

    this                  -- whoever is directly tupled to this relation
    computed_userset(r)   -- everyone in relation r of THIS object
                             ("every editor is also a viewer")
    tuple_to_userset(t,r) -- follow relation t to another object, then take
                             relation r there
                             ("a viewer of my parent folder is a viewer here")

`tuple_to_userset` is the interesting one: it is inheritance down a hierarchy,
and it is why "share the folder, everything inside is shared" works without
writing a tuple per file.

Why a whole system for this: the queries an application actually needs are

    check(object, relation, user)      may alice view this doc?      <- hot path
    expand(object, relation)           who can view this doc?        <- sharing UI
    list_objects(user, relation)       what can alice view?          <- the index page

and the third one is the killer. With permissions computed in application
code you cannot answer "what can this user see" without loading everything
and filtering, which is O(all documents) on every page load.

What this implementation leaves out from the real thing: zookies (the
consistency tokens that stop a "new enemy" from reading a doc using a stale
ACL cache), Leopard's flattened set index, and distribution. The evaluation
semantics are the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

# Depth cap. Nested groups can be cyclic ("A contains B contains A"), and a
# check that recurses forever is a denial of service you wrote yourself.
MAX_DEPTH = 25


@dataclass(frozen=True)
class Tuple:
    """object#relation@user, where user may itself be `object#relation`."""

    object: str      # "document:budget"
    relation: str    # "viewer"
    user: str        # "user:alice" or "group:finance#member"

    def __str__(self) -> str:
        return f"{self.object}#{self.relation}@{self.user}"

    @classmethod
    def parse(cls, text: str) -> "Tuple":
        object_part, rest = text.split("#", 1)
        relation, user = rest.split("@", 1)
        return cls(object_part, relation, user)

    @property
    def user_is_userset(self) -> bool:
        return "#" in self.user

    @property
    def userset(self) -> tuple[str, str] | None:
        if not self.user_is_userset:
            return None
        obj, rel = self.user.split("#", 1)
        return obj, rel


@dataclass
class Userset:
    """A userset rewrite rule."""

    kind: str  # "this" | "computed_userset" | "tuple_to_userset" | "union"
    relation: str | None = None            # computed_userset / tuple_to_userset target
    tupleset_relation: str | None = None   # tuple_to_userset: which relation to walk
    children: list["Userset"] = field(default_factory=list)

    @staticmethod
    def this() -> "Userset":
        return Userset("this")

    @staticmethod
    def computed(relation: str) -> "Userset":
        """Everyone in `relation` of this same object."""
        return Userset("computed_userset", relation=relation)

    @staticmethod
    def through(tupleset_relation: str, relation: str) -> "Userset":
        """Follow `tupleset_relation` to another object, take `relation` there."""
        return Userset(
            "tuple_to_userset", relation=relation, tupleset_relation=tupleset_relation
        )

    @staticmethod
    def union(*children: "Userset") -> "Userset":
        return Userset("union", children=list(children))


@dataclass
class Relation:
    name: str
    rewrite: Userset = field(default_factory=Userset.this)


@dataclass
class Namespace:
    """The type definition: which relations exist on `document`, `folder`, ..."""

    name: str
    relations: dict[str, Relation] = field(default_factory=dict)

    def relation(self, name: str, rewrite: Userset | None = None) -> "Namespace":
        self.relations[name] = Relation(name, rewrite or Userset.this())
        return self


class ReBAC:
    """A tuple store with check / expand / list_objects."""

    def __init__(self, max_depth: int = MAX_DEPTH) -> None:
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        self.max_depth = max_depth
        self.namespaces: dict[str, Namespace] = {}
        self.tuples: set[Tuple] = set()

    # ---- schema and data -------------------------------------------

    def namespace(self, name: str) -> Namespace:
        namespace = self.namespaces.setdefault(name, Namespace(name))
        return namespace

    def write(self, *tuples: Tuple | str) -> "ReBAC":
        for item in tuples:
            self.tuples.add(Tuple.parse(item) if isinstance(item, str) else item)
        return self

    def delete(self, *tuples: Tuple | str) -> "ReBAC":
        for item in tuples:
            self.tuples.discard(Tuple.parse(item) if isinstance(item, str) else item)
        return self

    # ---- evaluation -------------------------------------------------

    def _object_type(self, object_id: str) -> str:
        return object_id.split(":", 1)[0]

    def _rewrite_for(self, object_id: str, relation: str) -> Userset:
        namespace = self.namespaces.get(self._object_type(object_id))
        if namespace is None:
            return Userset.this()
        defined = namespace.relations.get(relation)
        return defined.rewrite if defined else Userset.this()

    def _direct(self, object_id: str, relation: str) -> Iterator[str]:
        for item in self.tuples:
            if item.object == object_id and item.relation == relation:
                yield item.user

    def check(
        self,
        object_id: str,
        relation: str,
        user: str,
        _depth: int = 0,
        _seen: frozenset[tuple[str, str, str]] | set[tuple[str, str, str]] | None = None,
    ) -> bool:
        """Is `user` in `relation` of `object_id`?"""
        if _depth > self.max_depth:
            return False
        seen = frozenset(_seen or ())
        key = (object_id, relation, user)
        if key in seen:
            # Cycle in the group graph. Returning False rather than raising
            # keeps a badly shaped tuple set from taking the service down.
            return False
        next_path = seen | {key}
        return self._check_userset(
            self._rewrite_for(object_id, relation),
            object_id,
            relation,
            user,
            _depth,
            next_path,
        )

    def _check_userset(
        self, rewrite: Userset, object_id: str, relation: str, user: str,
        depth: int, seen: frozenset[tuple[str, str, str]],
    ) -> bool:
        if rewrite.kind == "union":
            return any(
                self._check_userset(child, object_id, relation, user, depth, seen)
                for child in rewrite.children
            )

        if rewrite.kind == "this":
            for candidate in self._direct(object_id, relation):
                if candidate == user:
                    return True
                if "#" in candidate:
                    # The userset case: "group:finance#member". Recurse into
                    # that object's relation. Nested groups work because this
                    # step is itself a full check.
                    sub_object, sub_relation = candidate.split("#", 1)
                    if self.check(sub_object, sub_relation, user, depth + 1, seen):
                        return True
                if candidate.endswith(":*"):
                    # Public / wildcard grant: "document:x#viewer@user:*".
                    if user.startswith(candidate[:-1]):
                        return True
            return False

        if rewrite.kind == "computed_userset":
            return self.check(object_id, rewrite.relation or "", user, depth + 1, seen)

        if rewrite.kind == "tuple_to_userset":
            for parent in self._direct(object_id, rewrite.tupleset_relation or ""):
                target = parent.split("#", 1)[0]
                if self.check(target, rewrite.relation or "", user, depth + 1, seen):
                    return True
            return False

        return False

    def expand(
        self,
        object_id: str,
        relation: str,
        _depth: int = 0,
        _path: frozenset[tuple[str, str]] | None = None,
    ) -> dict:
        """The userset tree for a relation. This is what a sharing dialog shows."""
        if _depth > self.max_depth:
            return {"type": "depth_limit"}
        path = _path or frozenset()
        key = (object_id, relation)
        if key in path:
            return {"type": "cycle", "at": f"{object_id}#{relation}"}
        return self._expand_userset(
            self._rewrite_for(object_id, relation),
            object_id,
            relation,
            _depth,
            path | {key},
        )

    def _expand_userset(
        self,
        rewrite: Userset,
        object_id: str,
        relation: str,
        depth: int,
        path: frozenset[tuple[str, str]],
    ) -> dict:
        if rewrite.kind == "union":
            return {
                "type": "union",
                "children": [
                    self._expand_userset(child, object_id, relation, depth, path)
                    for child in rewrite.children
                ],
            }
        if rewrite.kind == "this":
            leaves, sets = [], []
            for candidate in sorted(self._direct(object_id, relation)):
                if "#" in candidate:
                    sub_object, sub_relation = candidate.split("#", 1)
                    sets.append(
                        {
                            "userset": candidate,
                            "expanded": self.expand(
                                sub_object, sub_relation, depth + 1, path
                            ),
                        }
                    )
                else:
                    leaves.append(candidate)
            return {"type": "this", "object": f"{object_id}#{relation}", "users": leaves,
                    "usersets": sets}
        if rewrite.kind == "computed_userset":
            return {
                "type": "computed_userset",
                "from": rewrite.relation,
                "expanded": self.expand(
                    object_id, rewrite.relation or "", depth + 1, path
                ),
            }
        if rewrite.kind == "tuple_to_userset":
            branches = []
            for parent in sorted(self._direct(object_id, rewrite.tupleset_relation or "")):
                target = parent.split("#", 1)[0]
                branches.append(
                    {
                        "via": f"{object_id}#{rewrite.tupleset_relation}@{parent}",
                        "expanded": self.expand(
                            target, rewrite.relation or "", depth + 1, path
                        ),
                    }
                )
            return {"type": "tuple_to_userset", "branches": branches}
        return {"type": "unknown"}

    def list_objects(self, user: str, relation: str, object_type: str) -> list[str]:
        """Every object of `object_type` where `user` has `relation`.

        The naive implementation: enumerate candidates and check each. Real
        Zanzibar maintains a reverse index (Leopard) precisely because this
        loop is O(objects) and sits on the page-load path. Written out here so
        the cost is visible rather than hidden behind an API.
        """
        candidates = {
            item.object for item in self.tuples if item.object.startswith(f"{object_type}:")
        }
        # Objects reachable only through a parent relation still count, so
        # include anything named as the target of a tuple as well.
        for item in self.tuples:
            target = item.user.split("#", 1)[0]
            if target.startswith(f"{object_type}:"):
                candidates.add(target)
        return sorted(obj for obj in candidates if self.check(obj, relation, user))

    def list_users(self, object_id: str, relation: str) -> list[str]:
        """Flatten expand() to the concrete subjects."""
        found: set[str] = set()

        def walk(node: dict) -> None:
            kind = node.get("type")
            if kind == "this":
                found.update(node.get("users", []))
                for entry in node.get("usersets", []):
                    walk(entry["expanded"])
            elif kind == "union":
                for child in node.get("children", []):
                    walk(child)
            elif kind == "computed_userset":
                walk(node["expanded"])
            elif kind == "tuple_to_userset":
                for branch in node.get("branches", []):
                    walk(branch["expanded"])

        walk(self.expand(object_id, relation))
        return sorted(found)


def google_drive_model() -> ReBAC:
    """The canonical worked example: documents inside folders, with groups.

        folder:  owner, editor, viewer (viewer inherits editor inherits owner)
        document: parent -> folder, plus its own owner/editor/viewer, and
                  anything you can do on the parent folder you can do here.
    """
    engine = ReBAC()
    engine.namespace("group").relation("member")
    engine.namespace("folder") \
        .relation("owner") \
        .relation("editor", Userset.union(Userset.this(), Userset.computed("owner"))) \
        .relation("viewer", Userset.union(Userset.this(), Userset.computed("editor")))
    engine.namespace("document") \
        .relation("parent") \
        .relation("owner") \
        .relation(
            "editor",
            Userset.union(
                Userset.this(),
                Userset.computed("owner"),
                Userset.through("parent", "editor"),
            ),
        ) \
        .relation(
            "viewer",
            Userset.union(
                Userset.this(),
                Userset.computed("editor"),
                Userset.through("parent", "viewer"),
            ),
        )
    return engine
