"""Provider detection tests — parametrized from providers.json."""

from __future__ import annotations

import json
from importlib import resources

import pytest

from is_antibot import AntibotResult, create_test_pattern, is_antibot

_PROVIDERS_DATA = json.loads(resources.files("is_antibot").joinpath("providers.json").read_text(encoding="utf-8"))
_ALL_PROVIDER_NAMES = {p["name"] for p in _PROVIDERS_DATA["providers"]}

# ---------------------------------------------------------------------------
# Positive detection cases: (id, kwargs, expected_provider, expected_detection)
# ---------------------------------------------------------------------------
POSITIVE_CASES: list[tuple[str, dict, str, str]] = [
    # -- cloudflare --
    ("cloudflare/headers/cf-mitigated", {"headers": {"cf-mitigated": "challenge"}}, "cloudflare", "headers"),
    ("cloudflare/cookies/cf_clearance", {"headers": {"set-cookie": "cf_clearance=abc123; path=/"}}, "cloudflare", "cookies"),
    # -- vercel --
    ("vercel/headers/x-vercel-mitigated", {"headers": {"x-vercel-mitigated": "challenge"}}, "vercel", "headers"),
    # -- akamai --
    ("akamai/headers/cache-status-error", {"headers": {"akamai-cache-status": "Error from child"}}, "akamai", "headers"),
    ("akamai/headers/grn", {"headers": {"akamai-grn": "test123"}}, "akamai", "headers"),
    ("akamai/cookies/abck", {"headers": {"set-cookie": "_abck=abc123~0~; path=/"}}, "akamai", "cookies"),
    ("akamai/html/bmak", {"html": '<script>bmak.sensor_data = "test";</script>'}, "akamai", "html"),
    # -- datadome --
    ("datadome/headers/x-dd-b=1", {"headers": {"x-dd-b": "1"}}, "datadome", "headers"),
    ("datadome/headers/x-dd-b=2", {"headers": {"x-dd-b": "2"}}, "datadome", "headers"),
    ("datadome/headers/x-datadome", {"headers": {"x-datadome": "test"}}, "datadome", "headers"),
    ("datadome/headers/x-datadome-cid", {"headers": {"x-datadome-cid": "abc123"}}, "datadome", "headers"),
    ("datadome/cookies/datadome", {"headers": {"set-cookie": "datadome=abc123; path=/"}}, "datadome", "cookies"),
    # -- perimeterx --
    ("perimeterx/headers/x-px-authorization", {"headers": {"x-px-authorization": "test"}}, "perimeterx", "headers"),
    ("perimeterx/html/window._pxAppId", {"html": '<script>window._pxAppId = "PX123";</script>'}, "perimeterx", "html"),
    ("perimeterx/html/pxInit", {"html": "<script>pxInit();</script>"}, "perimeterx", "html"),
    ("perimeterx/html/_pxAction", {"html": '<script>var _pxAction = "c";</script>'}, "perimeterx", "html"),
    ("perimeterx/cookies/px3", {"headers": {"set-cookie": "_px3=abc123; path=/"}}, "perimeterx", "cookies"),
    ("perimeterx/cookies/pxhd", {"headers": {"set-cookie": "_pxhd=abc123; path=/"}}, "perimeterx", "cookies"),
    # -- shapesecurity --
    ("shapesecurity/headers/dynamic-name", {"headers": {"x-abc12345-a": "test"}}, "shapesecurity", "headers"),
    ("shapesecurity/html/text", {"html": "<script>shapesecurity.init();</script>"}, "shapesecurity", "html"),
    # -- kasada --
    ("kasada/headers/x-kasada", {"headers": {"x-kasada": "test"}}, "kasada", "headers"),
    ("kasada/html/__kasada", {"html": "<script>__kasada.init();</script>"}, "kasada", "html"),
    # -- imperva --
    ("imperva/headers/x-cdn-incapsula", {"headers": {"x-cdn": "Incapsula"}}, "imperva", "headers"),
    ("imperva/html/incapsula", {"html": "<script>incapsula.init();</script>"}, "imperva", "html"),
    ("imperva/html/imperva", {"html": "<script>imperva.protect();</script>"}, "imperva", "html"),
    ("imperva/cookies/incap_ses", {"headers": {"set-cookie": "incap_ses_123=abc; path=/"}}, "imperva", "cookies"),
    ("imperva/cookies/visid_incap", {"headers": {"set-cookie": "visid_incap_456=xyz; path=/"}}, "imperva", "cookies"),
    ("imperva/cookies/reese84", {"headers": {"set-cookie": "reese84=abc123; path=/"}}, "imperva", "cookies"),
    # -- reblaze --
    ("reblaze/cookies/rbzid", {"headers": {"set-cookie": "rbzid=abc123; path=/"}}, "reblaze", "cookies"),
    ("reblaze/cookies/rbzsessionid", {"headers": {"set-cookie": "rbzsessionid=xyz; path=/"}}, "reblaze", "cookies"),
    ("reblaze/html/text", {"html": "<p>Protected by Reblaze</p>"}, "reblaze", "html"),
    # -- cheq --
    ("cheq/html/CheqSdk", {"html": "<script>CheqSdk.init();</script>"}, "cheq", "html"),
    ("cheq/html/cheqzone.com", {"html": '<script src="https://ob.cheqzone.com/script.js"></script>'}, "cheq", "html"),
    ("cheq/url/cheqzone.com", {"url": "https://ob.cheqzone.com/script.js"}, "cheq", "url"),
    ("cheq/url/cheq.ai", {"url": "https://cheq.ai/api/verify"}, "cheq", "url"),
    # -- sucuri --
    ("sucuri/html/text", {"html": "<p>Sucuri Website Firewall - Access Denied</p>"}, "sucuri", "html"),
    # -- threatmetrix --
    ("threatmetrix/html/text", {"html": "<script>ThreatMetrix.init();</script>"}, "threatmetrix", "html"),
    ("threatmetrix/url/fp-check-js", {"url": "https://example.com/fp/check.js?org_id=abc"}, "threatmetrix", "url"),
    # -- meetrics --
    ("meetrics/html/text", {"html": "<script>meetricsGlobal.init();</script>"}, "meetrics", "html"),
    ("meetrics/url/domain", {"url": "https://s418.mxcdn.net/bb-mx/serve/meetrics.com/script"}, "meetrics", "url"),
    # -- ocule --
    ("ocule/html/domain", {"html": '<script src="https://proxy.ocule.co.uk/script.js"></script>'}, "ocule", "html"),
    ("ocule/url/domain", {"url": "https://proxy.ocule.co.uk/script.js"}, "ocule", "url"),
    # -- recaptcha --
    ("recaptcha/url/recaptcha-api", {"url": "https://www.google.com/recaptcha/api.js"}, "recaptcha", "url"),
    ("recaptcha/url/google.com-recaptcha", {"url": "https://google.com/recaptcha/enterprise.js"}, "recaptcha", "url"),
    ("recaptcha/url/gstatic.com-recaptcha", {"url": "https://www.gstatic.com/recaptcha/releases/abc/recaptcha.js"}, "recaptcha", "url"),
    ("recaptcha/url/recaptcha.net", {"url": "https://recaptcha.net/recaptcha/api.js"}, "recaptcha", "url"),
    ("recaptcha/html/grecaptcha.execute", {"html": "<script>grecaptcha.execute();</script>"}, "recaptcha", "html"),
    ("recaptcha/html/g-recaptcha", {"html": '<div class="g-recaptcha" data-sitekey="test"></div>'}, "recaptcha", "html"),
    # -- hcaptcha --
    ("hcaptcha/url/domain", {"url": "https://hcaptcha.com/captcha/v1"}, "hcaptcha", "url"),
    ("hcaptcha/html/hcaptcha.com", {"html": '<script src="https://hcaptcha.com/1/api.js"></script>'}, "hcaptcha", "html"),
    ("hcaptcha/html/h-captcha", {"html": '<div class="h-captcha"></div>'}, "hcaptcha", "html"),
    # -- funcaptcha --
    ("funcaptcha/url/arkoselabs", {"url": "https://client-api.arkoselabs.com/fc/gc/"}, "funcaptcha", "url"),
    ("funcaptcha/url/funcaptcha", {"url": "https://api.funcaptcha.com/fc/gt2/public_key/test"}, "funcaptcha", "url"),
    ("funcaptcha/html/funcaptcha", {"html": "<script>funcaptcha.init();</script>"}, "funcaptcha", "html"),
    ("funcaptcha/html/arkoselabs.com", {"html": '<script src="https://client-api.arkoselabs.com/fc/assets/loader.js"></script>'}, "funcaptcha", "html"),
    # -- geetest --
    ("geetest/url/domain", {"url": "https://api.geetest.com/ajax.php"}, "geetest", "url"),
    ("geetest/html/text", {"html": "<script>geetest.init();</script>"}, "geetest", "html"),
    # -- cloudflare-turnstile --
    ("cloudflare-turnstile/url/api", {"url": "https://challenges.cloudflare.com/turnstile/v0/api.js"}, "cloudflare-turnstile", "url"),
    ("cloudflare-turnstile/html/cf-turnstile", {"html": '<div class="cf-turnstile"></div>'}, "cloudflare-turnstile", "html"),
    ("cloudflare-turnstile/html/api-script", {"html": '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'}, "cloudflare-turnstile", "html"),
    # -- friendly-captcha --
    ("friendly-captcha/url/domain", {"url": "https://cdn.friendlycaptcha.com/modules/v2/widget.js"}, "friendly-captcha", "url"),
    ("friendly-captcha/html/frc-captcha", {"html": '<div class="frc-captcha" data-sitekey="test"></div>'}, "friendly-captcha", "html"),
    ("friendly-captcha/html/friendlyChallenge", {"html": "<script>friendlyChallenge.render();</script>"}, "friendly-captcha", "html"),
    # -- captcha-eu --
    ("captcha-eu/url/domain", {"url": "https://www.captcha.eu/widget/api.js"}, "captcha-eu", "url"),
    ("captcha-eu/html/CaptchaEU", {"html": "<script>CaptchaEU.render();</script>"}, "captcha-eu", "html"),
    ("captcha-eu/html/captchaeu-widget", {"html": '<div class="captchaeu-widget"></div>'}, "captcha-eu", "html"),
    # -- qcloud-captcha --
    ("qcloud-captcha/url/domain", {"url": "https://turing.captcha.qcloud.com/tdc.js"}, "qcloud-captcha", "url"),
    ("qcloud-captcha/html/TencentCaptcha", {"html": '<script>new TencentCaptcha("appid");</script>'}, "qcloud-captcha", "html"),
    ("qcloud-captcha/html/turing.captcha", {"html": '<script src="//turing.captcha.gtimg.com/tdc.js"></script>'}, "qcloud-captcha", "html"),
    # -- aliexpress-captcha --
    ("aliexpress-captcha/url/x5secdata", {"url": "https://www.aliexpress.com/punish?x5secdata=abc123"}, "aliexpress-captcha", "url"),
    ("aliexpress-captcha/html/x5secdata", {"html": '<script>var x5secdata = "abc123";</script>'}, "aliexpress-captcha", "html"),
    # -- reddit --
    ("reddit/status_code/403", {"headers": {"content-type": "text/html", "server": "snooserv"}, "url": "https://www.reddit.com/r/digitalnomad/comments/1riz2r5/foo", "status_code": 403}, "reddit", "status_code"),
    ("reddit/html/blocked", {"html": "<div>blocked by network security.</div>", "url": "https://www.reddit.com/r/lotus/comments/1pzbv0z/foo"}, "reddit", "html"),
    # -- linkedin --
    ("linkedin/status_code/999", {"status_code": 999, "url": "https://www.linkedin.com/in/wesbos"}, "linkedin", "status_code"),
    # -- instagram --
    ("instagram/html/login-redirect", {"html": '<!DOCTYPE html><html lang="en"><head><title>Login \u2022 Instagram</title></head><body></body></html>', "url": "https://www.instagram.com/kikobeats/"}, "instagram", "html"),
    # -- youtube --
    ("youtube/html/empty-title", {"html": '<!DOCTYPE html><html><head><title> - YouTube</title></head><body><ytd-app disable-upgrade="true"></ytd-app></body></html>'}, "youtube", "html"),
    # -- anubis --
    ("anubis/html/script-tag", {"html": '<script id="anubis_challenge" type="application/json">{"rules":{"algorithm":"metarefresh"}}</script>'}, "anubis", "html"),
    ("anubis/html/static-path", {"html": '<img src="https://example.com/.within.website/x/cmd/anubis/static/img/pensive.webp">'}, "anubis", "html"),
    # -- aws-waf --
    ("aws-waf/headers/x-amzn-waf-action", {"headers": {"x-amzn-waf-action": "CHALLENGE"}}, "aws-waf", "headers"),
    ("aws-waf/html/aws-waf", {"html": "<script>aws-waf.init();</script>"}, "aws-waf", "html"),
    ("aws-waf/html/awswaf", {"html": '<script src="/awswaf/challenge.js"></script>'}, "aws-waf", "html"),
    ("aws-waf/cookies/aws-waf-token", {"headers": {"set-cookie": "aws-waf-token=abc123; path=/"}}, "aws-waf", "cookies"),
]

# ---------------------------------------------------------------------------
# Negative cases: (id, kwargs) — must NOT trigger detection
# ---------------------------------------------------------------------------
NEGATIVE_CASES: list[tuple[str, dict]] = [
    ("no-input", {}),
    ("empty-headers", {"headers": {}}),
    ("akamai/cache-hit-is-not-antibot", {"headers": {"akamai-cache-status": "HIT"}}),
    ("datadome/protected-is-not-antibot", {"headers": {"x-datadome": "protected"}}),
    ("recaptcha/grecaptcha-badge-css-is-not-antibot", {"html": '<style>.grecaptcha-badge{visibility:hidden}</style><title>My Video - YouTube</title>'}),
    ("hcaptcha/bare-mention-is-not-antibot", {"html": "<p>We use hcaptcha for bot protection.</p>"}),
    ("funcaptcha/bare-arkose-is-not-antibot", {"html": '<script>window.__arkose_config = {};</script><meta property="og:title" content="Real content">'}),
    ("geetest/generic-gt-js-is-not-antibot", {"html": '<script src="/static/gt.js"></script>'}),
    ("turnstile/bare-word-is-not-antibot", {"html": "<p>The subway turnstile was broken.</p>"}),
    ("reddit/blocked-html-on-non-reddit-url", {"html": "<div>blocked by network security.</div>", "url": "https://example.com/some/path"}),
    ("reddit/allowed-endpoint", {"headers": {"content-type": "application/json; charset=UTF-8", "server": "snooserv"}, "url": "https://www.reddit.com/r/lotus/comments/1pzbv0z/foo"}),
    ("linkedin/status-999-on-non-linkedin-url", {"status_code": 999, "url": "https://example.com"}),
    ("linkedin/no-antibot-without-status-999", {"headers": {"x-li-fabric": "prod-lor1", "set-cookie": "other=value; Max-Age=5"}, "status_code": 200}),
    ("youtube/normal-title", {"html": "<!DOCTYPE html><html><head><title>My Video - YouTube</title></head><body></body></html>"}),
    ("anubis/plain-text-mention", {"html": "<p>The template uses anubis_challenge as a key</p>", "headers": {}}),
    ("anubis/non-script-element", {"html": '<div id="anubis_challenge">some content</div>', "headers": {}}),
    ("anubis/within-website-in-text", {"html": "<p>Read more at within.website blog</p>", "headers": {}}),
]


@pytest.mark.parametrize(
    "kwargs,expected_provider,expected_detection",
    [pytest.param(kw, ep, ed, id=id_) for id_, kw, ep, ed in POSITIVE_CASES],
)
def test_detected(kwargs: dict, expected_provider: str, expected_detection: str):
    result = is_antibot(**kwargs)
    assert result == AntibotResult(detected=True, provider=expected_provider, detection=expected_detection)


@pytest.mark.parametrize(
    "kwargs",
    [pytest.param(kw, id=id_) for id_, kw in NEGATIVE_CASES],
)
def test_not_detected(kwargs: dict):
    result = is_antibot(**kwargs)
    assert result == AntibotResult(detected=False, provider=None, detection=None)


def test_every_provider_has_positive_coverage():
    """Ensure every provider in providers.json has at least one positive test case."""
    tested = {ep for _, _, ep, _ in POSITIVE_CASES}
    missing = _ALL_PROVIDER_NAMES - tested
    assert not missing, f"Providers without test coverage: {missing}"


def test_body_alias_falls_back_to_html():
    result = is_antibot(body="<script>grecaptcha.execute();</script>")
    assert result == AntibotResult(detected=True, provider="recaptcha", detection="html")


def test_fetch_response_with_headers_and_html():
    result = is_antibot(headers={"x-dd-b": "2"}, html="<script>grecaptcha.execute();</script>")
    assert result == AntibotResult(detected=True, provider="datadome", detection="headers")


def test_create_test_pattern_with_invalid_regex():
    has = create_test_pattern("test")
    assert has("[invalid(regex") is False


def test_is_antibot_with_invalid_regex_does_not_throw():
    result = is_antibot(url="test", html="test")
    assert result.detected is False
