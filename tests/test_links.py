"""The links file: who is which OS account on this machine (§2.2, §3.2)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from eugene_plexus_site_host.links import Links

from .conftest import link_entry, write_links


def test_a_missing_file_means_no_links_and_no_problem(tmp_path: Path) -> None:
    links = Links(tmp_path / "links.json")
    assert links.all() == [] and links.problem is None
    assert links.for_subject("a") is None and links.for_account("1") is None
    assert Links(None).all() == [] and Links(None).problem is None


def test_links_are_read_and_found_both_ways(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    write_links(path, link_entry("p1", "1001", "ada"), link_entry("p2", "1002", "bo"))
    links = Links(path)
    one = links.for_subject("p1")
    assert one is not None and one.account == "1001" and one.account_name == "HOST/ada"
    assert one.name == "ada"
    two = links.for_account("1002")
    assert two is not None and two.subject == "p2"
    assert [link.subject for link in links.all()] == ["p1", "p2"] and links.problem is None


def test_the_file_is_read_again_when_it_changes(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    write_links(path, link_entry("p1", "1001"))
    links = Links(path)
    assert links.for_subject("p2") is None
    write_links(path, link_entry("p1", "1001"), link_entry("p2", "1002"))
    # Same second, different size: the stamp is mtime and size.
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1_000_000_000))
    assert links.for_subject("p2") is not None
    write_links(path)
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 2_000_000_000))
    assert links.for_subject("p1") is None and links.all() == []


def test_a_file_that_appears_later_is_picked_up_and_one_that_goes_is_dropped(
    tmp_path: Path,
) -> None:
    path = tmp_path / "links.json"
    links = Links(path)
    assert links.all() == []
    write_links(path, link_entry("p1", "1001"))
    assert links.for_subject("p1") is not None
    path.unlink()
    assert links.for_subject("p1") is None and links.problem is None


def test_a_duplicate_subject_drops_both_entries(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    write_links(
        path,
        link_entry("p1", "1001"),
        link_entry("p2", "1002"),
        link_entry("p1", "1003"),
    )
    links = Links(path)
    # Neither of p1's entries survives; the unrelated link does.
    assert links.for_subject("p1") is None
    assert links.for_account("1001") is None and links.for_account("1003") is None
    assert [link.subject for link in links.all()] == ["p2"]


def test_a_duplicate_account_drops_both_entries(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    write_links(
        path,
        link_entry("p1", "1001"),
        link_entry("p2", "1002"),
        link_entry("p3", "1001"),
    )
    links = Links(path)
    assert links.for_subject("p1") is None and links.for_subject("p3") is None
    assert links.for_account("1001") is None
    assert [link.subject for link in links.all()] == ["p2"]


def test_a_third_entry_for_a_broken_pair_does_not_revive_it(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    write_links(
        path,
        link_entry("p1", "1001"),
        link_entry("p1", "1002"),
        link_entry("p1", "1003"),
        link_entry("p4", "1002"),
    )
    links = Links(path)
    assert links.all() == []
    assert all(links.for_account(a) is None for a in ("1001", "1002", "1003"))


def test_a_malformed_file_sets_a_problem_and_yields_no_links(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    for bad in (
        "{not json",
        json.dumps({"version": 2, "links": []}),
        json.dumps({"version": 1, "links": [{"subject": "p1"}]}),
        json.dumps({"version": 1, "links": [], "extra": 1}),
    ):
        path.write_text(bad, encoding="utf-8")
        links = Links(path)
        assert links.all() == [], bad
        assert links.problem is not None and "links file" in links.problem, bad


def test_a_file_put_right_clears_the_problem(tmp_path: Path) -> None:
    path = tmp_path / "links.json"
    path.write_text("nonsense", encoding="utf-8")
    links = Links(path)
    assert links.all() == [] and links.problem is not None
    write_links(path, link_entry("p1", "1001"))
    assert links.for_subject("p1") is not None and links.problem is None


def test_a_file_that_cannot_be_read_is_a_problem(tmp_path: Path) -> None:
    # A directory where the file should be: stat works, reading does not.
    path = tmp_path / "links.json"
    path.mkdir()
    links = Links(path)
    assert links.all() == [] and links.problem is not None
