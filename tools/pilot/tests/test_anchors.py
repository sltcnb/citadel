from pilot.anchors import anchor_status, extract_anchors, render_anchors

ALERT = """Éléments

Machine : srv-app01

Comptes : NT AUTHORITY\\SYSTEM, app_jdoe

Indicateurs : 10.20.30.10 (IP) ; 10.20.30.40 (IP)

Source port : 64721

Partage SMB : ADMIN$

La source a été recherchée (rendue sur admin_user1 et admin_user2).
dépôt du fichier testIsShareWriteable_zkvv0yha.quq
"""


def test_extracts_the_alert_observables():
    got = {(a.kind, a.value) for a in extract_anchors(ALERT)}
    assert ("port", "64721") in got
    assert ("ip", "10.20.30.40") in got and ("ip", "10.20.30.10") in got
    assert ("account", "app_jdoe") in got
    assert ("host", "srv-app01") in got
    assert ("share", "ADMIN$") in got
    assert ("file", "testIsShareWriteable_zkvv0yha.quq") in got


def test_builtin_and_narrative_accounts_are_not_anchors():
    accounts = {a.value for a in extract_anchors(ALERT) if a.kind == "account"}
    assert "SYSTEM" not in accounts
    # mentioned in the analyst's narrative, not labelled as alert accounts
    assert "admin_user1" not in accounts and "admin_user2" not in accounts


def test_unlabelled_service_accounts_are_still_found():
    assert ("account", "svc_backup") in {(a.kind, a.value) for a in extract_anchors("logon by svc_backup from 10.0.0.5")}


def test_status_tracks_what_was_queried_not_what_came_back():
    anchors = extract_anchors(ALERT)
    transcript = [
        {"step": 1, "action": "set_hypotheses", "thought": "port 64721 matters"},
        {"step": 2, "action": "search", "query": "message:*10.20.30.40*", "sample": ["…64721…"]},
        {"step": 3, "action": "aggregate", "agg_field": "evtx.event_id", "agg_query": "network.src_port:64721"},
    ]
    st = {(a.kind, a.value): step for a, step in anchor_status(anchors, transcript)}
    assert st[("ip", "10.20.30.40")] == 2
    assert st[("port", "64721")] == 3  # not step 1 (a thought) nor step 2 (a result)
    assert st[("account", "app_jdoe")] is None


def test_render_names_the_untested_with_a_recipe():
    out = render_anchors(anchor_status(extract_anchors(ALERT), []))
    assert "✘ port 64721" in out and "network.src_port:64721" in out
    assert render_anchors([]) == ""
