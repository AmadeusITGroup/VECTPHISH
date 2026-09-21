from main import IOCExtractor


def test_extract_iocs():
    emails = [
        {
            "sender": "security@fake-bank.com",
            "subject": "URGENT: Verify your account",
            "url": "https://fake-bank.com/login",
        },
        {
            "sender": "alert@malicious.com",
            "subject": "Security alert",
            "url": "https://malicious.com/verify",
        },
    ]

    result = IOCExtractor.extract_iocs(emails)

    assert "fake-bank.com" in result["sender_domains"]
    assert "malicious.com" in result["sender_domains"]

    assert "fake-bank.com" in result["url_domains"]
    assert "malicious.com" in result["url_domains"]

    assert "/login" in result["url_paths"]
    assert "/verify" in result["url_paths"]
