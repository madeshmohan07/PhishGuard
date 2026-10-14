"""
trusted_domains.py
-------------------
A curated list of well-known, real, legitimate domains spanning
technology, finance, media, government, education, retail, health, and
social categories.

Why this exists: the public training dataset (phishing_site_urls.csv)
draws its "good" (legitimate) examples almost entirely from deep,
specific pages (articles, forum threads, product pages) and contains
almost no bare-homepage URLs (e.g. "https://www.google.com"). Its
"bad" (phishing) examples, by contrast, include a much higher
proportion of short/bare URLs. Left uncorrected, a classifier trained
directly on this data learns to associate a *short path* with
phishing -- a spurious correlation that causes it to misclassify
everyday homepage visits (Google, Wikipedia, GitHub, etc.) as
phishing.

This mirrors exactly the fix already anticipated in the project
report (Section 7.2): supplementing the dataset with a reputable
top-domains list as a source of additional, correctly-labelled
legitimate URLs. No phishing URLs are fabricated to compensate --
only genuine, well-known legitimate domains are added.
"""

TRUSTED_DOMAINS = [
    # Search / tech platforms
    "google.com", "bing.com", "duckduckgo.com", "yahoo.com",
    "microsoft.com", "apple.com", "github.com", "gitlab.com",
    "stackoverflow.com", "stackexchange.com", "python.org", "npmjs.com",
    "mozilla.org", "w3.org", "cloudflare.com", "digitalocean.com",
    "atlassian.com", "slack.com", "zoom.us", "notion.so",
    # Social / communication
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com",
    "whatsapp.com", "telegram.org", "discord.com", "snapchat.com",
    # E-commerce / finance
    "amazon.com", "ebay.com", "paypal.com", "stripe.com",
    "etsy.com", "walmart.com", "target.com", "bestbuy.com",
    "visa.com", "mastercard.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "americanexpress.com", "coinbase.com",
    # Media / news
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com",
    "theguardian.com", "washingtonpost.com", "forbes.com", "bloomberg.com",
    "wsj.com", "npr.org", "aljazeera.com",
    # Entertainment / streaming
    "netflix.com", "spotify.com", "youtube.com", "twitch.tv",
    "hulu.com", "disneyplus.com", "soundcloud.com", "vimeo.com",
    # Education / reference
    "wikipedia.org", "khanacademy.org", "coursera.org", "edx.org",
    "mit.edu", "harvard.edu", "stanford.edu", "ox.ac.uk",
    "britannica.com", "wolframalpha.com",
    # Government / institutions
    "usa.gov", "irs.gov", "un.org", "who.int",
    "europa.eu", "gov.uk", "cdc.gov", "nasa.gov",
    # Cloud / productivity
    "dropbox.com", "box.com", "adobe.com", "salesforce.com",
    "wordpress.com", "wix.com", "squarespace.com", "shopify.com",
    "zendesk.com", "hubspot.com",
    # Travel
    "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com",
    "uber.com", "lyft.com", "delta.com", "united.com",
    # Health
    "mayoclinic.org", "webmd.com", "nih.gov", "healthline.com",
]

# A handful of realistic path suffixes used to diversify the legitimate
# class beyond bare homepages, so the model does not simply learn
# "any short URL from this exact list is safe" but instead sees a mix
# of path lengths for genuinely legitimate sites too.
COMMON_PATHS = [
    "", "/", "/about", "/login", "/help", "/search?q=example",
    "/en/", "/products", "/contact", "/account/settings",
]
