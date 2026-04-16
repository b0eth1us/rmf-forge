from app.services.column_mapper import suggest_mapping

def test_exact_match():
    result = suggest_mapping(["severity"])
    assert "severity" in result
    assert result["severity"][0]["original"] == "severity"

def test_alias_match():
    result = suggest_mapping(["Risk Level"])
    assert "severity" in result

def test_unmatched_column():
    result = suggest_mapping(["totally_custom_field_xyz"])
    assert any(
        item["original"] == "totally_custom_field_xyz"
        for item in result.get("__unmatched__", [])
    )

def test_multi_column():
    cols = ["Severity", "Vulnerability Name", "CWE", "Custom Field"]
    result = suggest_mapping(cols)
    assert "severity" in result
    assert "title" in result
    assert "cwe_id" in result
