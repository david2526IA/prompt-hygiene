from prompt_hygiene.scanner import scan


def test_scanner_redacts_and_classifies_high_risk_findings() -> None:
    report = scan("Contact ana@example.com. password=correct-horse and sk_abcdefghijklmnopqrstu")
    categories = {finding["category"] for finding in report["findings"]}
    assert {"email", "password_assignment", "api_key"} <= categories
    assert report["summary"]["high"] == 2
    assert "correct-horse" not in str(report["findings"])


def test_clean_text_has_no_review_requirement() -> None:
    report = scan("Summarize the advantages of unit testing.")
    assert report["summary"] == {"total": 0, "high": 0, "review_recommended": False}


def test_offsets_point_to_original_text() -> None:
    text = "mail me at user@example.org"
    finding = scan(text)["findings"][0]
    assert text[finding["start"]:finding["end"]] == "user@example.org"
