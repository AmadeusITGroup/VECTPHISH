from main import ATTACKClassifier


def test_phishing_attack_classification():
    campaign_data = {
        "sample_subjects": [
            "URGENT: Verify your account"
        ],
        "unique_url_domains": [
            "fake-bank.com"
        ],
        "url_patterns": [
            "/login"
        ],
        "detected_brands": [
            "bank of america"
        ],
        "urgency_keyword_usage": 1,
    }

    results = ATTACKClassifier.classify_campaign(campaign_data)

    technique_ids = [
        technique["technique_id"]
        for technique in results
    ]

    assert "T1566" in technique_ids
    assert "T1566.002" in technique_ids
