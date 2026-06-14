from pathlib import Path


from src.agentic_pipeline.run_pipeline import run_pipeline


FIXTURES = Path(__file__).parent / "fixtures"


def test_three_source_pipeline_generates_turtle(tmp_path):
    output = tmp_path / "out.ttl"
    raw_files = {
        "capec": [FIXTURES / "capec_sample.xml"],
        "attack": [FIXTURES / "attack_sample.json"],
        "icsa": [FIXTURES / "icsa_sample.csv"],
    }
    exit_code = run_pipeline(
        sources_to_fetch=None,
        raw_files=raw_files,
        output=str(output),
    )

    assert exit_code == 0
    assert output.exists()

    ttl = output.read_text(encoding="utf-8")
    assert "CAPEC-66" in ttl
    assert "T1190" in ttl
    assert "ICSA-24-001-01" in ttl
    assert "hasRelatedWeakness" in ttl
    assert "hasCAPEC" in ttl
    assert "hasCVE" in ttl
