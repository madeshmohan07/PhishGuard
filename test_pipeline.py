"""Run with:  python -m unittest discover -s tests -v   (from the project root)
These are the automated versions of the Review 1 test cases TC01-TC10."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from app import app  # noqa: E402


class PhishGuardTests(unittest.TestCase):
    def setUp(self):
        self.c = app.test_client()

    def predict(self, url):
        return self.c.post("/api/predict", json={"url": url})

    def test_tc01_legitimate_url(self):
        d = self.predict("https://www.wikipedia.org").get_json()
        self.assertEqual(d["label"], "legitimate")

    def test_tc02_phishing_style_url(self):
        d = self.predict("http://bankofamerica.com.verify-identity.co/login.php").get_json()
        self.assertEqual(d["label"], "phishing")

    def test_tc03_ip_address_url(self):
        d = self.predict("http://192.168.4.12/wp-login/verify").get_json()
        self.assertEqual(d["label"], "phishing")
        self.assertEqual(d["features"]["has_ip_address"], 1)

    def test_tc04_suspicious_keywords(self):
        d = self.predict("http://secure-paypal-update.account-verify.info/confirm").get_json()
        self.assertEqual(d["label"], "phishing")

    def test_tc05_special_characters(self):
        d = self.predict("http://accounts-verify@@secure--bank.info").get_json()
        self.assertTrue(d["ok"])
        self.assertGreater(d["features"]["num_hyphens"], 2)

    def test_tc06_url_shortener(self):
        d = self.predict("http://bit.ly/3xKq9zT").get_json()
        self.assertEqual(d["features"]["is_shortened"], 1)
        self.assertEqual(d["label"], "phishing")

    def test_tc07_invalid_url(self):
        r = self.predict("htp:/notaurl")
        self.assertEqual(r.status_code, 400)

    def test_tc08_empty_input(self):
        r = self.predict("")
        self.assertEqual(r.status_code, 400)

    def test_tc09_long_url(self):
        r = self.predict("http://example.com/" + "a" * 3000)
        self.assertEqual(r.status_code, 400)
        d = self.predict("http://example.com/" + "a" * 250).get_json()
        self.assertTrue(d["ok"])

    def test_tc10_unseen_url_returns_confidence(self):
        d = self.predict("https://brand-new-site-12345.example.org/page").get_json()
        self.assertTrue(d["ok"])
        self.assertTrue(0 <= d["confidence"] <= 100)

    def test_homepage_bias_regression(self):
        for u in ["https://www.google.com", "https://www.github.com", "https://www.nasa.gov"]:
            self.assertEqual(self.predict(u).get_json()["label"], "legitimate", u)

    def test_https_does_not_decide_the_result(self):
        a = self.predict("http://secure-paypal-update.account-verify.info/confirm").get_json()
        b = self.predict("https://secure-paypal-update.account-verify.info/confirm").get_json()
        self.assertEqual(a["label"], b["label"])

    def test_health_and_home(self):
        self.assertEqual(self.c.get("/health").status_code, 200)
        self.assertEqual(self.c.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
