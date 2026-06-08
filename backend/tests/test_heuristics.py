from app.services.heuristics import (
    calculate_entropy,
    check_homograph_attack,
    check_suspicious_tld,
    check_redirect_chain,
    check_brand_impersonation,
    extract_domain_features,
    score_url_heuristics,
)


class TestCalculateEntropy:
    def test_empty_string(self):
        assert calculate_entropy("") == 0.0

    def test_single_char(self):
        assert calculate_entropy("a") == 0.0

    def test_repetitive(self):
        assert calculate_entropy("aaaa") == 0.0

    def test_diverse(self):
        entropy = calculate_entropy("abcdefghij")
        assert entropy > 0

    def test_high_entropy(self):
        entropy = calculate_entropy("x7k9m2p4q8")
        assert entropy > 3.0


class TestHomographAttack:
    def test_no_homograph(self):
        is_homo, chars = check_homograph_attack("google.com")
        assert is_homo is False
        assert chars == []

    def test_with_homograph(self):
        is_homo, chars = check_homograph_attack("gооgle.com")
        assert is_homo is True
        assert len(chars) > 0

    def test_cyrillic_chars(self):
        is_homo, chars = check_homograph_attack("аррӏе.com")
        assert is_homo is True


class TestSuspiciousTLD:
    def test_safe_tld(self):
        assert check_suspicious_tld("google.com") == "low"

    def test_suspicious_tld(self):
        assert check_suspicious_tld("malware.xyz") == "high"

    def test_medium_tld(self):
        assert check_suspicious_tld("site.toolongtld") == "medium"


class TestRedirectChain:
    def test_no_redirect(self):
        url, hops = check_redirect_chain("https://example.com/page")
        assert len(hops) == 0

    def test_with_redirect(self):
        url, hops = check_redirect_chain(
            "https://example.com/page?redirect=http://evil.com"
        )
        assert "redirect" in hops


class TestBrandImpersonation:
    def test_no_impersonation(self):
        result = check_brand_impersonation("https://google.com")
        assert result is None

    def test_paypal_impersonation(self):
        result = check_brand_impersonation("https://paypa1.com/login")
        assert result == "paypal"


class TestDomainFeatures:
    def test_basic_features(self):
        features = extract_domain_features("https://example.com/path")
        assert features["uses_https"] is True
        assert features["url_length"] > 0

    def test_ip_address(self):
        features = extract_domain_features("http://192.168.1.1/login")
        assert features["has_ip_address"] is True

    def test_at_symbol(self):
        features = extract_domain_features("https://evil.com@real.com")
        assert features["has_at_symbol"] is True


class TestScoreHeuristics:
    def test_safe_url(self):
        features = extract_domain_features("https://google.com")
        score = score_url_heuristics(features)
        assert score < 30

    def test_suspicious_url(self):
        features = extract_domain_features(
            "http://192.168.1.1/phishing-login-verify-account.html"
        )
        score = score_url_heuristics(features)
        assert score > 50
