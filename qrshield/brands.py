"""Brand, TLD and keyword intelligence used by the URL risk model.

These lists are intentionally maintained as data (not logic) so they can be
extended without retraining the model. The model uses them as *features*;
the rule engine uses them to explain a verdict.
"""

from __future__ import annotations

# brand name -> official registrable domains
BRANDS = {
    # Big tech / accounts
    "google": {"google.com", "google.co.uk", "google.de", "google.ca", "google.com.au", "google.co.in", "gmail.com", "youtube.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com", "apple.co.uk", "apple.com.au"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "microsoftstore.com", "xbox.com", "bing.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.com.au", "amazon.in", "amazon.co.jp", "amazonaws.com", "audible.com", "primevideo.com"},
    "paypal": {"paypal.com", "paypal.me", "paypal.co.uk", "paypal.de"},
    "netflix": {"netflix.com", "netflix.co.uk"},
    "meta": {"facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com", "meta.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "tiktok": {"tiktok.com", "tiktokv.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "snapchat": {"snapchat.com", "snap.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "adobe": {"adobe.com", "adobelogin.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "spotify": {"spotify.com", "spotify.link"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "roblox": {"roblox.com", "rbx.com", "rbxcdn.com"},
    "epicgames": {"epicgames.com", "fortnite.com"},
    "playstation": {"playstation.com", "sony.com"},
    "xbox": {"xbox.com", "microsoft.com"},
    "nintendo": {"nintendo.com", "nintendo.co.uk"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "gitlab": {"gitlab.com"},
    "cloudflare": {"cloudflare.com", "workers.dev"},
    "aws": {"amazonaws.com", "aws.amazon.com"},
    "azure": {"azure.com", "microsoft.com"},
    "openai": {"openai.com", "chatgpt.com"},
    "anthropic": {"anthropic.com", "claude.ai"},

    # Payments / finance / crypto
    "visa": {"visa.com", "visa.co.uk"},
    "mastercard": {"mastercard.com", "mastercard.us"},
    "stripe": {"stripe.com"},
    "wise": {"wise.com", "transferwise.com"},
    "revolut": {"revolut.com"},
    "monzo": {"monzo.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.us"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "lloyds": {"lloydsbank.com", "lloyds.com"},
    "natwest": {"natwest.com", "natwest.co.uk"},
    "santander": {"santander.com", "santander.co.uk", "santanderbank.com"},
    "nationwide": {"nationwide.co.uk", "nationwide.com"},
    "halifax": {"halifax.co.uk"},
    "coinbase": {"coinbase.com", "coinbase.co.uk"},
    "binance": {"binance.com", "binance.us"},
    "kraken": {"kraken.com"},
    "crypto.com": {"crypto.com"},
    "metamask": {"metamask.io"},
    "trustwallet": {"trustwallet.com"},
    "ledger": {"ledger.com"},
    "blockchain": {"blockchain.com"},
    "cashapp": {"cash.app", "square.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com", "zelle.com"},
    "payoneer": {"payoneer.com"},
    "skrill": {"skrill.com"},
    "neteller": {"neteller.com"},

    # India / South Asia
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com"},
    "icici": {"icicibank.com", "icicilombard.com", "icicidirect.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "statebankofindia.com"},
    "axis": {"axisbank.com", "axisbank.co.in"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "pnb": {"pnbindia.in", "pnb.co.in"},
    "bob": {"bankofbaroda.in", "bankofbaroda.com"},
    "canara": {"canarabank.com"},
    "idfc": {"idfcfirstbank.com", "idfcbank.com"},
    "yesbank": {"yesbank.in"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"google.com", "gpay.app"},
    "upi": {"npci.org.in", "upi.npci.org.in"},
    "bhim": {"npci.org.in"},
    "airtel": {"airtel.in", "airtel.com"},
    "jio": {"jio.com", "jiomart.com"},
    "vi": {"myvi.in", "vodafoneidea.com"},
    "bsnl": {"bsnl.co.in", "bsnl.in"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "lic": {"licindia.in"},
    "epfo": {"epfindia.gov.in", "epfindia.com"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "gst": {"gst.gov.in"},
    "uidai": {"uidai.gov.in", "aadhaar.uidai.gov.in"},
    "digilocker": {"digilocker.gov.in"},
    "cowin": {"cowin.gov.in"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "swiggy": {"swiggy.com"},
    "zomato": {"zomato.com"},
    "ola": {"olacabs.com", "olacabs.in"},
    "uber": {"uber.com"},
    "makemytrip": {"makemytrip.com"},

    # Retail / logistics / services
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de", "ebay.in"},
    "walmart": {"walmart.com", "walmart.ca", "walmart.com.mx"},
    "target": {"target.com"},
    "costco": {"costco.com", "costco.co.uk"},
    "bestbuy": {"bestbuy.com", "bestbuy.ca"},
    "ikea": {"ikea.com", "ikea.co.uk", "ikea.in"},
    "aliexpress": {"aliexpress.com", "aliexpress.ru"},
    "alibaba": {"alibaba.com"},
    "etsy": {"etsy.com"},
    "shein": {"shein.com", "shein.co.uk"},
    "temu": {"temu.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.uk", "dhl-usa.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com", "usps.gov"},
    "royalmail": {"royalmail.com", "royalmail.co.uk"},
    "dpd": {"dpd.com", "dpd.co.uk", "dpd.de"},
    "hermes": {"hermesworld.com", "myhermes.co.uk"},
    "evri": {"evri.com"},
    "purolator": {"purolator.com"},
    "canadapost": {"canadapost-postescanada.ca"},
    "auspost": {"auspost.com.au"},
    "docusign": {"docusign.com", "docusign.net"},
    "hellosign": {"hellosign.com", "dropbox.com"},
    "box": {"box.com"},
    "wetransfer": {"wetransfer.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "booking": {"booking.com"},
    "airbnb": {"airbnb.com", "airbnb.co.uk"},
    "expedia": {"expedia.com", "expedia.co.uk"},
    "tripadvisor": {"tripadvisor.com"},
    "lyft": {"lyft.com"},
    "doordash": {"doordash.com"},
    "instacart": {"instacart.com"},
    "grubhub": {"grubhub.com"},
    "ubereats": {"ubereats.com"},
    "xboxlive": {"xbox.com"},
    "twitch": {"twitch.tv"},
    "reddit": {"reddit.com", "redd.it"},
    "pinterest": {"pinterest.com", "pin.it"},
    "yahoo": {"yahoo.com", "yahoo.co.uk", "yahoo.co.in"},
    "aol": {"aol.com"},
    "protonmail": {"proton.me", "protonmail.com"},
    "zoho": {"zoho.com", "zohomail.com"},
    "godaddy": {"godaddy.com"},
    "namecheap": {"namecheap.com"},
    "hostinger": {"hostinger.com"},
    "bluehost": {"bluehost.com"},
    "cpanel": {"cpanel.net"},
    "wordpress": {"wordpress.com", "wordpress.org"},
    "wix": {"wix.com"},
    "squarespace": {"squarespace.com"},
    "weebly": {"weebly.com"},
    "canva": {"canva.com"},
    "figma": {"figma.com"},
    "notion": {"notion.so", "notion.com"},
    "slack": {"slack.com"},
    "teams": {"microsoft.com", "teams.microsoft.com"},
    "trello": {"trello.com", "atlassian.com"},
    "atlassian": {"atlassian.com", "bitbucket.org"},
    "salesforce": {"salesforce.com", "force.com"},
    "oracle": {"oracle.com"},
    "ibm": {"ibm.com"},
    "dell": {"dell.com"},
    "hp": {"hp.com"},
    "lenovo": {"lenovo.com"},
    "samsung": {"samsung.com"},
    "sony": {"sony.com"},
    "lg": {"lg.com"},
    "nike": {"nike.com"},
    "adidas": {"adidas.com"},
    "zara": {"zara.com"},
    "hm": {"hm.com"},
    "uniqlo": {"uniqlo.com"},
}

# High-abuse TLDs regularly seen in quishing campaigns. Not inherently bad,
# but each one raises the prior probability of abuse.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "icu", "buzz", "monster", "rest",
    "cam", "surf", "bar", "beauty", "hair", "skin", "makeup", "quest",
    "cyou", "bond", "sbs", "cfd", "click", "link", "online", "site",
    "website", "space", "store", "shop", "live", "life", "world", "today",
    "fun", "host", "press", "rocks", "work", "fit", "fail", "gq", "ml",
    "ga", "cf", "tk", "su", "pw", "cc", "ws", "to", "am", "fm", "gg",
    "dev", "app", "pages", "support", "help", "info", "biz", "pro",
    "vip", "win", "bid", "loan", "download", "stream", "review", "party",
    "trade", "date", "men", "racing", "accountant", "science", "agency",
    "email", "digital", "network", "solutions", "services", "center",
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co",
    "uk", "de", "fr", "it", "es", "nl", "be", "ch", "at", "se", "no",
    "dk", "fi", "pl", "cz", "pt", "gr", "ru", "ua", "in", "au", "nz",
    "ca", "us", "mx", "br", "ar", "cl", "jp", "cn", "kr", "sg", "hk",
    "tw", "my", "ph", "th", "vn", "id", "pk", "bd", "ng", "ke", "za",
    "il", "tr", "sa", "ae", "eg",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "tr.im", "tiny.cc", "lnkd.in",
    "rb.gy", "cutt.ly", "shorturl.at", "s.id", "rebrand.ly", "bl.ink",
    "t.ly", "v.gd", "shorte.st", "shrinkme.io", "clck.ru", "surl.li",
    "short.io", "linktr.ee", "beacons.ai", "trib.al", "dlvr.it",
    "qrco.de", "qr.link", "qrd.by", "qurl.com", "wa.me", "t.me",
}

# Platforms where anybody can publish a page, frequently abused for phishing
# because the initial domain looks trustworthy.
FREE_HOSTING_SUFFIXES = {
    "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io",
    "blogspot.com", "weebly.com", "wixsite.com", "squarespace.com",
    "myshopify.com", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "storage.googleapis.com", "glitch.me", "repl.co",
    "replit.app", "onrender.com", "surge.sh", "now.sh", "appspot.com",
    "webflow.io", "carrd.co", "notion.site", "canva.site", "linktr.ee",
    "beacons.ai", "taplink.cc", "bio.link", "mystrikingly.com",
    "wordpress.com", "tumblr.com", "wix.com", "godaddysites.com",
    "000webhostapp.com", "byethost.com", "infinityfreeapp.com",
    "rf.gd", "42web.io", "free.nf", "epizy.com", "duckdns.org",
    "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "serveo.net",
    "ngrok.io", "ngrok-free.app", "loca.lt", "trycloudflare.com",
}

SUSPICIOUS_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "sign_on", "auth",
    "authenticate", "verification", "verify", "validate", "confirm",
    "account", "accounts", "update", "secure", "security", "alert",
    "notification", "unlock", "recover", "recovery", "reset", "password",
    "passwd", "credential", "banking", "bank", "wallet", "billing",
    "invoice", "payment", "pay", "refund", "transaction", "transfer",
    "claim", "reward", "bonus", "gift", "prize", "winner", "lottery",
    "delivery", "parcel", "shipping", "package", "tracking", "track",
    "customs", "fee", "tax", "fine", "suspended", "blocked", "locked",
    "expire", "expired", "urgent", "immediately", "act-now", "limited",
    "support", "helpdesk", "service", "customer", "official", "safe",
    "webscr", "cmd", "dispatch", "session", "token", "oauth", "sso",
}

PAYMENT_KEYWORDS = {
    "upi", "paytm", "phonepe", "gpay", "bhim", "netbanking", "net-banking",
    "debit", "credit", "card", "cvv", "otp", "ifsc", "upi-id", "vpa",
    "refund", "cashback", "payment", "pay", "billing", "invoice",
    "razorpay", "payu", "billdesk", "instamojo", "ccavenue",
}

CRYPTO_KEYWORDS = {
    "bitcoin", "btc", "ethereum", "eth", "usdt", "tether", "solana",
    "crypto", "blockchain", "wallet", "metamask", "trustwallet", "binance",
    "coinbase", "airdrop", "presale", "ido", "seed-phrase", "seedphrase",
    "private-key", "metamask-wallet", "wallet-connect", "walletconnect",
}

LOGIN_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "auth", "password", "reset", "unlock",
    "confirm", "billing", "payment", "webscr", "oauth", "sso",
}

REDIRECT_PARAMETERS = {
    "url", "uri", "link", "redirect", "redirect_url", "redirect_uri",
    "redirect_uri", "return", "returnurl", "return_url", "returnto",
    "next", "continue", "dest", "destination", "target", "goto", "go",
    "out", "away", "to", "r", "u", "target_url", "forward",
}

DANGEROUS_SCHEMES = {
    "javascript", "data", "file", "vbscript", "about", "blob", "jar",
    "chrome", "ms-msdt", "search-ms", "ms-officecmd",
}

OFFICIAL_BRAND_DOMAINS = set()
for _domains in BRANDS.values():
    OFFICIAL_BRAND_DOMAINS.update(_domains)

# Short second-level labels that are too generic to count as a brand token.
GENERIC_LABELS = {
    "www", "app", "web", "mail", "login", "secure", "account", "my",
    "online", "shop", "store", "pay", "payment", "support", "help",
    "service", "auth", "sso", "signin", "portal", "home", "official",
    "verify", "update", "m", "mobile", "new", "get", "go", "link",
}
