
# ── Leitura do .env ──────────────────────────────────────────────────────────
import os
from datetime import datetime
import requests

def load_env_local(env_path=".env"):
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# Carrega variáveis do .env local
load_env_local(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

BASE_URL = os.environ.get("VICARIUS_BASE_URL", "https://atacadao.vicarius.cloud")
TOKEN = os.environ.get("VICARIUS_API_KEY", "API_KEY")

API_URL = (
    f"{BASE_URL}/vicarius-external-data-api/aggregation/searchGroup"
    "?from=0&size=100"
    "&objectName=OrganizationEndpointVulnerabilities"
    "&includeOriginalDoc=true"
    "&sort=aggregationId"
    "&sumLastSubAggregationBuckets=1"
    "&group=vulnerabilityId%3BendpointId"
    "&q=vulnerabilityId%3Din%3D(444299%2C425277%2C418038%2C412439%2C396991%2C356428%2C337332%2C217735)"
    "%3BorganizationEndpointVulnerabilitiesVulnerability.vulnerabilityCISARequiredAction%3Dex%3D(true)"
)

headers = {
    "accept": "application/json, text/plain, */*",
    "vicarius-token": TOKEN,
}

# ── Fetch ─────────────────────────────────────────────────────────────────────
response = requests.get(API_URL, headers=headers)
data = response.json()

total = data.get("serverResponseCount", 0)
buckets = data.get("serverResponseObject", [])

# ── Extração de linhas ────────────────────────────────────────────────────────
def ts_to_date(ts_ms):
    """Converte timestamp em milissegundos para data legível."""
    if not ts_ms:
        return "-"
    try:
        return datetime.fromtimestamp(int(ts_ms) / 1000).strftime("%Y-%m-%d")
    except Exception:
        return "-"

rows = []
for bucket in buckets:
    doc = bucket.get("aggregationModelAbs", {})

    vuln     = doc.get("organizationEndpointVulnerabilitiesVulnerability", {})
    endpoint = doc.get("organizationEndpointVulnerabilitiesEndpoint", {})
    product  = doc.get("organizationEndpointVulnerabilitiesProduct", {})
    pub      = doc.get("organizationEndpointVulnerabilitiesPublisher", {})
    patch    = doc.get("organizationEndpointVulnerabilitiesPatch", {})
    ext_ref  = vuln.get("vulnerabilityExternalReference", {})
    severity = vuln.get("vulnerabilitySensitivityLevel", {})

    # KEV = campo de texto com a ação requerida pela CISA
    kev_action = vuln.get("vulnerabilityCISARequiredAction", "")
    kev        = "SIM" if kev_action else "NÃO"

    patch_name = patch.get("patchName") or "-"
    endpoints_affected = 0
    for agg in bucket.get("aggregationAggregations", []):
        if agg.get("aggregationName") == "endpointIds":
            endpoints_affected = agg.get("aggregationCount", 0)

    rows.append({
        "VulnID"    : str(doc.get("vulnerabilityId", "-")),
        "CVE"       : ext_ref.get("externalReferenceExternalId", "-"),
        "Produto"   : product.get("productName", "-"),
        "Publisher" : pub.get("publisherName", "-"),
        "Versão"    : doc.get("organizationEndpointVulnerabilitiesVersion", {}).get("versionName", "-"),
        "Severity"  : severity.get("sensitivityLevelName", "-"),
        "CVSSv3"    : str(vuln.get("vulnerabilityV3BaseScore", "0.0")),
        "KEV"       : kev,
        "Patch"     : patch_name,
        "Endpoints" : str(endpoints_affected),
        "Endpoint"  : endpoint.get("endpointName", "-"),
        "Alive"     : "Sim" if endpoint.get("endpointAlive") else "Não",
        "Publicado" : ts_to_date(vuln.get("vulnerabilityPublishedAt")),
    })

# ── Impressão da tabela ───────────────────────────────────────────────────────
COLS = ["VulnID", "CVE", "Produto", "Publisher", "Versão",
        "Severity", "CVSSv3", "KEV", "Patch", "Endpoints", "Endpoint", "Alive", "Publicado"]

# Largura dinâmica por coluna
widths = {col: len(col) for col in COLS}
for row in rows:
    for col in COLS:
        widths[col] = max(widths[col], len(row[col]))

sep = "+-" + "-+-".join("-" * widths[c] for c in COLS) + "-+"

def print_row(values):
    print("| " + " | ".join(f"{values[c]:<{widths[c]}}" for c in COLS) + " |")

print(f"\nTotal de vulnerabilidades: {total}  |  Exibindo: {len(rows)}\n")
print(sep)
print_row({c: c for c in COLS})   # cabeçalho
print(sep)
for row in rows:
    print_row(row)
print(sep)

# ── Legenda KEV ───────────────────────────────────────────────────────────────
print("\nKEV = Known Exploited Vulnerability (CISA Required Action presente)")
print("Todos os resultados acima possuem KEV = SIM pois o filtro '=ex=(true)' já exige o campo.\n")

# ── Detalhe KEV por vulnerabilidade ──────────────────────────────────────────
print("─" * 80)
print("AÇÃO REQUERIDA PELA CISA (KEV detail):")
print("─" * 80)
seen = set()
for bucket in buckets:
    doc  = bucket.get("aggregationModelAbs", {})
    vuln = doc.get("organizationEndpointVulnerabilitiesVulnerability", {})
    vid  = doc.get("vulnerabilityId")
    cve  = vuln.get("vulnerabilityExternalReference", {}).get("externalReferenceExternalId", "-")
    action = vuln.get("vulnerabilityCISARequiredAction", "")
    if vid not in seen and action:
        seen.add(vid)
        print(f"\n[{vid}] {cve}")
        print(f"  {action}")
