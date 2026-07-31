"""The published site must not link to things that only exist before the build.

The site is built by MkDocs: docs/foo.md becomes /foo/, and the .md file itself
is not published. docs/index.html, however, is copied verbatim -- MkDocs does
not rewrite links inside static files. So a link written as "foo.md" in the
playground renders fine on GitHub and 404s on the published site.

That is exactly the failure this repository already shipped once: before the
MkDocs build existed, every .md link out of the playground landed on raw,
unrendered Markdown, including the 14-day plan. CI was green throughout,
because nothing checked what the site actually served.

These tests need no dependencies, so they run in the ordinary suite rather than
only in the docs workflow.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PLAYGROUND = DOCS / "index.html"
MKDOCS_YML = ROOT / "mkdocs.yml"

# href="..." that points somewhere inside the site (not http(s), not an anchor,
# not a mailto).
INTERNAL_HREF = re.compile(r'href="(?!https?:|mailto:|#)([^"]+)"')


def playground_html() -> str:
    return PLAYGROUND.read_text(encoding="utf-8")


class TestPlaygroundLinks(unittest.TestCase):
    def test_playground_never_links_to_raw_markdown(self) -> None:
        """A .md link from index.html 404s once MkDocs has built the site."""
        offenders = [
            href
            for href in INTERNAL_HREF.findall(playground_html())
            if href.split("#")[0].endswith(".md")
        ]
        self.assertEqual(
            offenders,
            [],
            "docs/index.html links to Markdown files by filename. MkDocs "
            "publishes docs/foo.md as /foo/ and does not publish foo.md, so "
            "these would 404 on the site. Link to 'foo/' instead.",
        )

    def test_playground_page_links_have_a_source_document(self) -> None:
        """Every /foo/ link must correspond to a docs/foo.md that will build."""
        missing = []
        for href in INTERNAL_HREF.findall(playground_html()):
            target = href.split("#")[0]
            if not target.endswith("/"):
                continue  # assets and in-page controls, not page links
            name = target.rstrip("/")
            if not (DOCS / f"{name}.md").is_file():
                missing.append(target)
        self.assertEqual(
            missing,
            [],
            "docs/index.html links to pages with no docs/<name>.md to build "
            "them from; these would 404 on the published site.",
        )


class TestMkDocsNav(unittest.TestCase):
    def test_every_nav_entry_exists(self) -> None:
        """A nav entry naming a missing file fails the build; catch it here."""
        text = MKDOCS_YML.read_text(encoding="utf-8")
        # Nav entries look like "  - ラベル: 09_attack_matrix.md".
        targets = re.findall(r"^\s+-\s+[^:\n]+:\s*([A-Za-z0-9_./-]+\.md)\s*$", text, re.M)
        self.assertTrue(targets, "no nav entries found in mkdocs.yml")
        missing = [t for t in targets if not (DOCS / t).is_file()]
        self.assertEqual(missing, [], "mkdocs.yml nav references missing files")

    def test_site_dir_does_not_clobber_the_repository(self) -> None:
        """MkDocs deletes site_dir on every build, so it must not be real work.

        site/ holds a checked-in playground build; pointing site_dir there
        would delete it on the next docs build.
        """
        text = MKDOCS_YML.read_text(encoding="utf-8")
        match = re.search(r"^site_dir:\s*(\S+)\s*$", text, re.M)
        self.assertIsNotNone(match, "mkdocs.yml must set site_dir explicitly")
        site_dir = match.group(1).strip().strip("\"'").rstrip("/")
        self.assertNotIn(
            site_dir,
            {"site", "docs", "authlab", "tests", "drills", "attacks", "scripts"},
            f"site_dir={site_dir!r} names a tracked directory MkDocs would delete",
        )


class TestDocsCrossLinks(unittest.TestCase):
    def test_markdown_does_not_link_out_of_the_docs_tree(self) -> None:
        """'../authlab/x.py' resolves on GitHub but not on the built site.

        Links to source files have to be absolute GitHub URLs so that they work
        from both the repository view and the published page.
        """
        offenders = []
        for md in sorted(DOCS.glob("*.md")):
            for target in re.findall(r"\]\((\.\./[^)]+)\)", md.read_text(encoding="utf-8")):
                offenders.append(f"{md.name} -> {target}")
        self.assertEqual(
            offenders,
            [],
            "documentation links outside docs/ with a relative path; MkDocs "
            "cannot resolve these. Use the full https://github.com/... URL.",
        )


if __name__ == "__main__":
    unittest.main()
