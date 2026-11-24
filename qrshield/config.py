"""Project paths and tunable constants."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
REPORTS_DIR = ARTIFACTS_DIR / "reports"

_env_model = os.environ.get("QR_SHIELD_MODEL")
MODEL_PATH = (
    Path(_env_model).expanduser() if _env_model else ARTIFACTS_DIR / "qrshield_model.joblib"
)
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
ALLOWLIST_PATH = PROJECT_ROOT / "allowlist.txt"

_env_db = os.environ.get("QR_SHIELD_DB")
HISTORY_DB_PATH = (
    Path(_env_db).expanduser() if _env_db else DATA_DIR / "qrshield.db"
)

# Verdict thresholds. The fine-grained operating points are stored in the
# trained artifact; these are only fallbacks for an untrained install.
DEFAULT_SUSPICIOUS_THRESHOLD = 0.35
DEFAULT_MALICIOUS_THRESHOLD = 0.65

# Maximum characters analysed from a single payload (defensive limit).
MAX_URL_LENGTH = 4096
MAX_PAYLOAD_LENGTH = 8192
MAX_NESTED_URLS = 5

# Common registrable-domain suffixes used as a fast fallback if tldextract
# fails for a host.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.kr", "or.kr", "go.kr", "ac.kr",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
    "co.id", "or.id", "web.id", "ac.id", "go.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph",
    "co.th", "in.th", "or.th", "go.th", "ac.th",
    "com.vn", "net.vn", "org.vn", "gov.vn",
    "com.pk", "net.pk", "org.pk", "gov.pk",
    "com.bd", "net.bd", "org.bd", "gov.bd",
    "com.ng", "net.ng", "org.ng", "gov.ng",
    "co.ke", "or.ke", "go.ke", "ac.ke",
    "com.eg", "net.eg", "org.eg", "gov.eg",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
    "com.ua", "net.ua", "org.ua", "gov.ua",
    "com.pl", "net.pl", "org.pl", "gov.pl",
    "co.at", "or.at", "gv.at", "ac.at",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "gov.pt",
    "com.gr", "net.gr", "org.gr", "gov.gr",
    "com.ru", "net.ru", "org.ru", "gov.ru",
    "com.co", "net.co", "org.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "gob.pe",
    "com.uy", "net.uy", "org.uy", "gub.uy",
    "co.ve", "com.ve", "net.ve", "org.ve", "gob.ve",
    "com.ec", "net.ec", "org.ec", "gob.ec",
    "com.bo", "net.bo", "org.bo", "gob.bo",
    "com.py", "net.py", "org.py", "gov.py",
    "co.cr", "com.cr", "or.cr", "go.cr",
    "com.do", "net.do", "org.do", "gob.do",
    "com.gt", "net.gt", "org.gt", "gob.gt",
    "com.sv", "net.sv", "org.sv", "gob.sv",
    "com.hn", "net.hn", "org.hn", "gob.hn",
    "com.ni", "net.ni", "org.ni", "gob.ni",
    "com.pa", "net.pa", "org.pa", "gob.pa",
    "co.ma", "net.ma", "org.ma", "gov.ma",
    "com.dz", "net.dz", "org.dz", "gov.dz",
    "com.tn", "net.tn", "org.tn", "gov.tn",
    "com.lb", "net.lb", "org.lb", "gov.lb",
    "com.jo", "net.jo", "org.jo", "gov.jo",
    "com.kw", "net.kw", "org.kw", "gov.kw",
    "com.qa", "net.qa", "org.qa", "gov.qa",
    "com.bh", "net.bh", "org.bh", "gov.bh",
    "com.om", "net.om", "org.om", "gov.om",
}
