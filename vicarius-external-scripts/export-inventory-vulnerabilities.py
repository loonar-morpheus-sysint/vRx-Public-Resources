import argparse
import csv
import json
import os
import sys
import time
import math
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SCRIPT_RELATIVE_PATH = os.path.relpath(os.path.abspath(__file__), REPO_ROOT)

# Configuração padrão
DEFAULT_BASE_URL = "https://atacadao.vicarius.cloud"
DEFAULT_ENV_FILE = ".env"
DEFAULT_INCIDENT_PAGE_SIZE = 500
DEFAULT_ENDPOINT_PAGE_SIZE = 500
DEFAULT_ATTRIBUTE_PAGE_SIZE = 500
DEFAULT_INVENTORY_CACHE_DIR = os.path.join(
    SCRIPT_DIR,
    "cache",
    "vicarius_inventory",
)
DEFAULT_INCIDENT_PARTITION_MAX_RECORDS = 5000
DEFAULT_INVENTORY_PARTITION_MAX_RECORDS = 5000
OUTPUT_JSONL = os.path.join(SCRIPT_DIR, "vicarius_vulnerabilities.jsonl")
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "vicarius_vulnerabilities.csv")

# Limites e controle de requests
MAX_RETRIES = 5
REQUEST_TIMEOUT = 30
MAX_PAGE_SIZE = 500
PARTITION_COUNT_TOLERANCE = 1
MAX_PARTITION_REFINEMENT_DEPTH = 6
MAX_INITIAL_INCIDENT_PARTITIONS = 128

# Delays e cooldowns
ENDPOINT_PAGE_DELAY = 0.05
ATTRIBUTE_PAGE_DELAY = 0.35
INCIDENT_PAGE_DELAY = 0.30
INCIDENT_MAX_SAFE_PAGES = 20
INCIDENT_PARTITION_COOLDOWN_EVERY = 10
INCIDENT_PARTITION_COOLDOWN_SECONDS = 2.0
ATTRIBUTE_WARMUP_DELAY = 5.0
ATTRIBUTE_FETCH_PARTITION_MAX_RECORDS = 4000
INCIDENT_FETCH_PARTITION_MAX_RECORDS = 4000
ATTRIBUTE_ENDPOINT_IDS_PER_PARTITION = 200
REQUEST_PACING_BY_PATH = {
    "/vicarius-external-data-api/endpointAttributes/search": 5.00,
    "/vicarius-external-data-api/incidentEvent/filter": 0.50,
    "/vicarius-external-data-api/incidentEvent/count": 0.20,
}
ATTRIBUTE_PARTITION_COOLDOWN_EVERY = 8
ATTRIBUTE_PARTITION_COOLDOWN_SECONDS = 15.0

# Regras de enriquecimento
ATTRIBUTE_MATCHERS = {
    "internal_ip": {
        "exact_names": ("Internal IP Address",),
        "contains_terms": ("internal ip",),
    },
    "external_ip": {
        "exact_names": ("External IP Address",),
        "contains_terms": ("external ip", "public ip"),
    },
    "organizational_unit": {
        "exact_names": ("Organizational Unit", "Organization Unit", "OU"),
        "contains_terms": ("organizational unit", "organization unit", "ou"),
    },
    "operating_system_version": {
        "exact_names": (
            "Operating System Version",
            "OS Version",
            "Operating System Build",
        ),
        "contains_terms": ("operating system version", "os version", "build"),
    },
    "mac_address": {
        "exact_names": ("MAC Address", "MAC Address ID"),
        "contains_terms": ("mac",),
    },
}
RELEVANT_ATTRIBUTE_SOURCES = {
    source_name.casefold()
    for matcher in ATTRIBUTE_MATCHERS.values()
    for source_name in matcher["exact_names"]
}
ENDPOINT_INCLUDE_FIELDS = (
    "endpointId,endpointName,endpointCreatedAt,endpointOperatingSystem.operatingSystemName,"
    "endpointOrganization.organizationName,"
    "endpointEndpointExternalReferences.endpointExternalReferencesExternalReference.externalReferenceExternalId,"
    "endpointEndpointExternalReferences.endpointExternalReferencesExternalReference.externalReferenceExternalReferenceSource.externalReferenceSourceName"
)
OPERATING_SYSTEM_INCLUDE_FIELDS = (
    "publisherId,operatingSystemId,"
    "organizationPublisherOperatingSystemsPublisher.publisherName,"
    "organizationPublisherOperatingSystemsOperatingSystem.operatingSystemName"
)
ENDPOINT_ATTRIBUTE_INCLUDE_FIELDS = (
    "endpointAttributesEndpoint.endpointId,endpointAttributesEndpoint.endpointName,"
    "endpointAttributesAttribute.attributeExternalId,"
    "endpointAttributesAttribute.attributeAttributeSource.attributeSourceName"
)
INVENTORY_CACHE_ENDPOINTS_FILE = "endpoints.jsonl"
INVENTORY_CACHE_ATTRIBUTES_FILE = "endpoint_attributes.jsonl"
INVENTORY_CACHE_METADATA_FILE = "metadata.json"
DETECTED_VULNERABILITY_QUERY = "incidentEventIncidentEventType=in=(DetectedVulnerability)"
INCIDENT_PARTITION_FIELD = "analyticsEventCreatedAtNano"
ENDPOINT_PARTITION_FIELD = "endpointCreatedAt"
ATTRIBUTE_PARTITION_FIELD = "endpointId"
REQUEST_PACING_STATE = {}


def configure_console_output():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(line_buffering=True, write_through=True)


def format_duration(total_seconds):
    total_seconds = max(0, int(total_seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def load_env_file(env_path=DEFAULT_ENV_FILE):
    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value


def build_headers(api_key):
    return {
        "Accept": "application/json",
        "Vicarius-Token": api_key,
    }


def get_runtime_settings():
    incident_page_size = normalize_page_size(
        DEFAULT_INCIDENT_PAGE_SIZE,
        "incident-page-size",
    )
    endpoint_page_size = normalize_page_size(
        DEFAULT_ENDPOINT_PAGE_SIZE,
        "endpoint-page-size",
    )
    attribute_page_size = normalize_page_size(
        DEFAULT_ATTRIBUTE_PAGE_SIZE,
        "attribute-page-size",
    )

    return {
        "incident_page_size": incident_page_size,
        "endpoint_page_size": endpoint_page_size,
        "attribute_page_size": attribute_page_size,
    }


def get_api_configuration():
    api_key = os.getenv("VICARIUS_API_KEY", "").strip()
    base_url = os.getenv("VICARIUS_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")

    if not api_key or api_key.lower() == "replace_me":
        raise SystemExit(
            "Defina VICARIUS_API_KEY no arquivo .env ou nas variáveis de ambiente."
        )

    return api_key, base_url


def validate_execution_mode(args):
    if args.refresh_inventory_cache:
        return "refresh-cache"

    if args.use_inventory_cache:
        return "export-with-cache"

    raise SystemExit(
        "Use somente um dos fluxos suportados: `--refresh-inventory-cache` ou `--use-inventory-cache --from-date ... --to-date ...`."
    )


def first_non_empty(*values):
    for value in values:
        if value is None:
            continue

        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                return normalized
            continue

        if value != "":
            return value

    return ""


def clean_text(value):
    if value is None:
        return ""

    text = str(value)
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def normalize_ip(value):
    text = clean_text(value)

    if not text:
        return ""

    if "/" in text:
        ip_part, suffix = text.split("/", 1)
        if suffix.isdigit():
            return ip_part

    return text


def request_json(session, url, headers, params=None, timeout=REQUEST_TIMEOUT):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            pacing_key, min_interval = get_request_pacing_rule(url)
            wait_for_request_slot(pacing_key, min_interval)

            response = session.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=timeout,
            )

            update_request_pacing(pacing_key, response.status_code)

            if response.status_code == 200:
                return response.json(), response.status_code

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_seconds = 5 * attempt
                if retry_after and retry_after.isdigit():
                    wait_seconds = max(wait_seconds, int(retry_after))

                register_request_backoff(pacing_key, wait_seconds)

                if attempt < MAX_RETRIES:
                    print(
                        f"Limite de taxa da API em {url}. Aguardando {wait_seconds}s antes da tentativa {attempt + 1}/{MAX_RETRIES}..."
                    )
                    time.sleep(wait_seconds)
                    continue

                print(
                    f"Limite de taxa da API em {url}. Requisição abortada após {MAX_RETRIES} tentativa(s)."
                )
                break

            if response.status_code == 400:
                try:
                    response_payload = response.json()
                except Exception:
                    response_payload = {}

                result = response_payload.get("serverResponseResult", {})
                result_code = result.get("serverResponseResultCode", "")
                result_message = result.get("serverResponseResultMessage", "")

                if result_code == "PARAMETER_VALUE_EXCEEDED_LIMIT":
                    print(
                        f"Limite de paginação da API detectado em {url}; a partição será refinada."
                    )
                    return response_payload, response.status_code

                print(
                    f"Erro API (400) em {url}: {result_code or result_message or 'bad request'}"
                )

            print(f"Erro API ({response.status_code}) em {url}")
        except Exception as exc:
            print(f"Erro request em {url}: {exc}")

        if attempt < MAX_RETRIES:
            time.sleep(2)

    return {}, None


def get_request_pacing_rule(url):
    path = urlparse(url).path

    for suffix, min_interval in REQUEST_PACING_BY_PATH.items():
        if path.endswith(suffix):
            return suffix, min_interval

    return path, 0.0


def wait_for_request_slot(pacing_key, min_interval):
    if min_interval <= 0:
        return

    state = REQUEST_PACING_STATE.setdefault(
        pacing_key,
        {
            "last_request_at": 0.0,
            "rate_limited_until": 0.0,
        },
    )
    base_wait_until = state["last_request_at"] + min_interval
    rate_limited_until = state.get("rate_limited_until", 0.0)
    wait_until = max(base_wait_until, rate_limited_until)
    remaining = wait_until - time.monotonic()

    if remaining > 0:
        if rate_limited_until > base_wait_until + 0.5:
            print(
                f"Pacing ativo para {pacing_key}: aguardando {remaining:.1f}s para respeitar o rate limit do endpoint..."
            )
        time.sleep(remaining)


def register_request_backoff(pacing_key, wait_seconds):
    state = REQUEST_PACING_STATE.setdefault(
        pacing_key,
        {
            "last_request_at": 0.0,
            "rate_limited_until": 0.0,
        },
    )
    state["rate_limited_until"] = max(
        state.get("rate_limited_until", 0.0),
        time.monotonic() + max(0.0, float(wait_seconds)),
    )


def update_request_pacing(pacing_key, status_code):
    state = REQUEST_PACING_STATE.setdefault(
        pacing_key,
        {
            "last_request_at": 0.0,
            "rate_limited_until": 0.0,
        },
    )
    now = time.monotonic()
    state["last_request_at"] = now

    if status_code == 200 and state.get("rate_limited_until", 0.0) <= now:
        state["rate_limited_until"] = 0.0


def convert_date(ms):
    try:
        if not ms:
            return ""
        return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%d")
    except Exception:
        return ""


def parse_cli_datetime(value, option_name, is_end=False):
    normalized = clean_text(value)
    if not normalized:
        raise SystemExit(f"{option_name} não pode ser vazio.")

    try:
        is_date_only = "T" not in normalized and " " not in normalized
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(
            f"{option_name} inválido: {value!r}. Use formato ISO 8601, por exemplo 2026-03-22 ou 2026-03-22T14:30:00."
        ) from exc

    if is_date_only:
        parsed = parsed.replace(
            hour=23 if is_end else 0,
            minute=59 if is_end else 0,
            second=59 if is_end else 0,
            microsecond=999999 if is_end else 0,
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    else:
        parsed = parsed.astimezone(UTC)

    return parsed


def datetime_to_nanos(value):
    return int(value.timestamp() * 1_000_000_000)


def resolve_incident_date_range(args):
    if not args.from_date or not args.to_date:
        raise SystemExit(
            "A exportação exige --use-inventory-cache com --from-date e --to-date."
        )

    from_date = parse_cli_datetime(args.from_date, "--from-date")
    to_date = parse_cli_datetime(args.to_date, "--to-date", is_end=True)

    if to_date < from_date:
        raise SystemExit(
            "Intervalo inválido: --to-date deve ser maior ou igual a --from-date."
        )

    return from_date, to_date


def build_incident_filter_query(from_date=None, to_date=None):
    range_query = build_numeric_range_query(
        INCIDENT_PARTITION_FIELD,
        datetime_to_nanos(from_date) if from_date else None,
        datetime_to_nanos(to_date) if to_date else None,
    )
    return build_query(DETECTED_VULNERABILITY_QUERY, range_query)


def severity(score):

    if score is None:
        return "Unknown"

    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"

    return "Unknown"


def fetch_all_pages(
    session,
    headers,
    url,
    page_size,
    max_pages=None,
    page_delay=0,
    label="registros",
    extra_params=None,
    return_metadata=False,
):
    offset = 0
    pages = 0
    items = []
    total_count = None
    last_status_code = 200
    overflow_detected = False

    while True:
        if max_pages is not None and pages >= max_pages:
            break

        payload, status_code = request_json(
            session,
            url,
            headers,
            params={
                "from": offset,
                "size": page_size,
                **(extra_params or {}),
            },
        )
        last_status_code = status_code

        if status_code != 200:
            if status_code == 400:
                result = payload.get("serverResponseResult", {})
                overflow_detected = (
                    result.get("serverResponseResultCode")
                    == "PARAMETER_VALUE_EXCEEDED_LIMIT"
                )
            break

        if total_count is None:
            reported_count = payload.get("serverResponseCount")
            if isinstance(reported_count, int) and reported_count >= 0:
                total_count = reported_count

        page_items = payload.get("serverResponseObject", [])
        if not page_items:
            break

        items.extend(page_items)
        pages += 1

        if pages == 1 or pages % 5 == 0:
            if total_count is not None:
                print(
                    f"  {label}: página {pages}, acumulado {len(items)}/{total_count}"
                )
            else:
                print(f"  {label}: página {pages}, acumulado {len(items)}")

        if len(page_items) < page_size:
            break

        offset += page_size

        if total_count is not None and offset >= total_count:
            break

        if page_delay > 0:
            time.sleep(page_delay)

    if return_metadata:
        return items, last_status_code, overflow_detected

    return items


def build_query(*parts):
    return ";".join(part for part in parts if part)


def build_numeric_range_query(field_name, range_start=None, range_end=None):
    clauses = []

    if range_start is not None:
        clauses.append(f"{field_name}>{int(range_start) - 1}")

    if range_end is not None:
        clauses.append(f"{field_name}<{int(range_end) + 1}")

    return build_query(*clauses)


def fetch_total_count(
    session,
    headers,
    url,
    q="",
    include_fields=None,
    sort=None,
    extra_params=None,
    include_paging=True,
):
    params = {}

    if include_paging:
        params.update(
            {
                "from": 0,
                "size": 1,
            }
        )

    if q:
        params["q"] = q

    if include_fields:
        params["includeFields"] = include_fields

    if sort:
        params["sort"] = sort

    if extra_params:
        params.update(extra_params)

    payload, status_code = request_json(session, url, headers, params=params)

    if status_code != 200:
        return None, payload, status_code

    return payload.get("serverResponseCount", 0), payload, status_code


def fetch_first_record(
    session,
    headers,
    url,
    include_fields=None,
    q="",
    sort=None,
):
    params = {
        "from": 0,
        "size": 1,
    }

    if include_fields:
        params["includeFields"] = include_fields

    if q:
        params["q"] = q

    if sort:
        params["sort"] = sort

    payload, status_code = request_json(session, url, headers, params=params)

    if status_code != 200:
        return None

    records = payload.get("serverResponseObject", [])
    if not records:
        return None

    return records[0]


def discover_numeric_bounds(
    session,
    headers,
    url,
    field_name,
    include_fields=None,
    q="",
):
    first_record = fetch_first_record(
        session,
        headers,
        url,
        include_fields=include_fields,
        q=q,
        sort=f"+{field_name}",
    )
    last_record = fetch_first_record(
        session,
        headers,
        url,
        include_fields=include_fields,
        q=q,
        sort=f"-{field_name}",
    )

    if not first_record or not last_record:
        return None, None

    return first_record.get(field_name), last_record.get(field_name)


def build_numeric_partitions(
    session,
    headers,
    url,
    field_name,
    range_start,
    range_end,
    max_records,
    base_query="",
    count_url=None,
    count_extra_params=None,
    count_include_paging=True,
):
    if range_start is None or range_end is None:
        return []

    if range_start > range_end:
        return []

    query = build_query(
        base_query,
        build_numeric_range_query(field_name, range_start, range_end),
    )

    count, _, status_code = fetch_total_count(
        session,
        headers,
        count_url or url,
        q=query,
        extra_params=count_extra_params,
        include_paging=count_include_paging,
    )
    if status_code != 200 or count in (None, 0):
        return []

    partition = {
        "field": field_name,
        "start": int(range_start),
        "end": int(range_end),
        "count": int(count),
        "query": query,
    }

    if count <= max_records or range_start >= range_end:
        return [partition]

    midpoint = (int(range_start) + int(range_end)) // 2
    if midpoint < range_start or midpoint >= range_end:
        return [partition]

    left_partitions = build_numeric_partitions(
        session,
        headers,
        url,
        field_name,
        range_start,
        midpoint,
        max_records,
        base_query=base_query,
        count_url=count_url,
        count_extra_params=count_extra_params,
        count_include_paging=count_include_paging,
    )
    right_partitions = build_numeric_partitions(
        session,
        headers,
        url,
        field_name,
        midpoint + 1,
        range_end,
        max_records,
        base_query=base_query,
        count_url=count_url,
        count_extra_params=count_extra_params,
        count_include_paging=count_include_paging,
    )

    if not left_partitions and not right_partitions:
        return [partition]

    return left_partitions + right_partitions


def build_fallback_numeric_subpartitions(
    session,
    headers,
    url,
    field_name,
    range_start,
    range_end,
    base_query="",
    count_url=None,
    count_extra_params=None,
    count_include_paging=True,
):
    if range_start is None or range_end is None or range_start >= range_end:
        return []

    midpoint = (int(range_start) + int(range_end)) // 2
    if midpoint < range_start or midpoint >= range_end:
        return []

    partitions = []
    for start, end in ((range_start, midpoint), (midpoint + 1, range_end)):
        query = build_query(
            base_query,
            build_numeric_range_query(field_name, start, end),
        )
        count, _, status_code = fetch_total_count(
            session,
            headers,
            count_url or url,
            q=query,
            extra_params=count_extra_params,
            include_paging=count_include_paging,
        )
        if status_code != 200 or count in (None, 0):
            continue

        partitions.append(
            {
                "field": field_name,
                "start": int(start),
                "end": int(end),
                "count": int(count),
                "query": query,
            }
        )

    return partitions


def build_endpoint_id_partition(endpoint_ids, field_name=ATTRIBUTE_PARTITION_FIELD):
    if not endpoint_ids:
        return None

    return {
        "field": field_name,
        "start": int(endpoint_ids[0]),
        "end": int(endpoint_ids[-1]),
        "count": None,
        "query": build_numeric_range_query(field_name, endpoint_ids[0], endpoint_ids[-1]),
        "_endpoint_ids": list(endpoint_ids),
    }


def build_endpoint_id_partitions(endpoint_ids, partition_size):
    partitions = []
    normalized_ids = sorted({int(endpoint_id) for endpoint_id in endpoint_ids})

    for index in range(0, len(normalized_ids), max(1, int(partition_size))):
        partition = build_endpoint_id_partition(
            normalized_ids[index : index + max(1, int(partition_size))]
        )
        if partition:
            partitions.append(partition)

    return partitions


def split_endpoint_id_partition(partition):
    endpoint_ids = partition.get("_endpoint_ids") or []
    if len(endpoint_ids) < 2:
        return []

    midpoint = len(endpoint_ids) // 2
    left_partition = build_endpoint_id_partition(endpoint_ids[:midpoint], partition["field"])
    right_partition = build_endpoint_id_partition(endpoint_ids[midpoint:], partition["field"])

    return [item for item in (left_partition, right_partition) if item]


def is_partition_fetch_complete(expected_count, fetched_count):
    if expected_count is None:
        return True

    return abs(int(fetched_count) - int(expected_count)) <= PARTITION_COUNT_TOLERANCE


def fetch_partitioned_pages(
    session,
    headers,
    url,
    page_size,
    page_delay,
    label,
    partitions,
    include_fields=None,
    max_records=None,
    base_query="",
    refinement_depth=0,
    count_url=None,
    count_extra_params=None,
    count_include_paging=True,
):
    items = []
    partition_summaries = []
    request_path = urlparse(url).path

    for index, partition in enumerate(partitions, start=1):
        should_proactively_refine = (
            max_records is not None
            and isinstance(partition.get("count"), int)
            and int(partition["count"]) > int(max_records)
            and refinement_depth < MAX_PARTITION_REFINEMENT_DEPTH
            and partition["start"] < partition["end"]
        )

        if should_proactively_refine:
            refined_partitions = build_numeric_partitions(
                session,
                headers,
                url,
                partition["field"],
                partition["start"],
                partition["end"],
                max_records,
                base_query=base_query,
                count_url=count_url,
                count_extra_params=count_extra_params,
                count_include_paging=count_include_paging,
            )

            if (
                refined_partitions
                and not (
                    len(refined_partitions) == 1
                    and refined_partitions[0]["start"] == partition["start"]
                    and refined_partitions[0]["end"] == partition["end"]
                )
            ):
                print(
                    f"Refinando {label} partição [{partition['start']}, {partition['end']}] antes da coleta por exceder {max_records} registro(s)..."
                )
                refined_items, refined_summaries = fetch_partitioned_pages(
                    session,
                    headers,
                    url,
                    page_size,
                    page_delay,
                    label,
                    refined_partitions,
                    include_fields=include_fields,
                    max_records=max_records,
                    base_query=base_query,
                    refinement_depth=refinement_depth + 1,
                    count_url=count_url,
                    count_extra_params=count_extra_params,
                    count_include_paging=count_include_paging,
                )
                items.extend(refined_items)
                partition_summaries.extend(refined_summaries)
                continue

        partition_label = (
            f"{label} partição {index}/{len(partitions)} "
            f"[{partition['start']}, {partition['end']}]"
        )
        print(
            f"Carregando {partition_label} com {partition['count']} registro(s) esperados..."
        )

        extra_params = {
            "q": partition["query"],
        }
        if include_fields:
            extra_params["includeFields"] = include_fields

        partition_items, last_status_code, overflow_detected = fetch_all_pages(
            session,
            headers,
            url,
            page_size,
            page_delay=page_delay,
            label=partition_label,
            extra_params=extra_params,
            return_metadata=True,
        )

        fetched_count = len(partition_items)
        expected_count = partition.get("count")
        if expected_count is None:
            complete = not overflow_detected and last_status_code == 200
        else:
            complete = (
                not overflow_detected
                and is_partition_fetch_complete(expected_count, fetched_count)
            )

        should_refine = (
            (overflow_detected or not complete)
            and refinement_depth < MAX_PARTITION_REFINEMENT_DEPTH
            and partition["start"] < partition["end"]
        )

        if should_refine:
            refined_partitions = split_endpoint_id_partition(partition)

            if not refined_partitions and max_records is not None:
                refined_max_records = max(
                    1,
                    min(int(max_records), int(partition.get("count") or max_records) // 2),
                )
                refined_partitions = build_numeric_partitions(
                    session,
                    headers,
                    url,
                    partition["field"],
                    partition["start"],
                    partition["end"],
                    refined_max_records,
                    base_query=base_query,
                    count_url=count_url,
                    count_extra_params=count_extra_params,
                    count_include_paging=count_include_paging,
                )

                if (
                    not refined_partitions
                    or len(refined_partitions) == 1
                    and refined_partitions[0]["start"] == partition["start"]
                    and refined_partitions[0]["end"] == partition["end"]
                ):
                    refined_partitions = build_fallback_numeric_subpartitions(
                        session,
                        headers,
                        url,
                        partition["field"],
                        partition["start"],
                        partition["end"],
                        base_query=base_query,
                        count_url=count_url,
                        count_extra_params=count_extra_params,
                        count_include_paging=count_include_paging,
                    )

            if refined_partitions:
                print(
                    f"Refinando {partition_label} após coletar {fetched_count}/{partition['count']} registro(s)..."
                )
                refined_items, refined_summaries = fetch_partitioned_pages(
                    session,
                    headers,
                    url,
                    page_size,
                    page_delay,
                    label,
                    refined_partitions,
                    include_fields=include_fields,
                    max_records=max_records,
                    base_query=base_query,
                    refinement_depth=refinement_depth + 1,
                    count_url=count_url,
                    count_extra_params=count_extra_params,
                    count_include_paging=count_include_paging,
                )
                items.extend(refined_items)
                partition_summaries.extend(refined_summaries)
                continue

        items.extend(partition_items)

        partition_summaries.append(
            {
                **{
                    key: value
                    for key, value in partition.items()
                    if not key.startswith("_")
                },
                "fetched": fetched_count,
                "complete": complete,
            }
        )

        if (
            request_path.endswith("/vicarius-external-data-api/endpointAttributes/search")
            and index % ATTRIBUTE_PARTITION_COOLDOWN_EVERY == 0
            and index < len(partitions)
        ):
            print(
                f"Pausa preventiva de {ATTRIBUTE_PARTITION_COOLDOWN_SECONDS:.0f}s após {index} partições de atributos para evitar throttling..."
            )
            time.sleep(ATTRIBUTE_PARTITION_COOLDOWN_SECONDS)

    return items, partition_summaries


def normalize_page_size(page_size, label):
    normalized = max(1, int(page_size))

    if normalized > MAX_PAGE_SIZE:
        print(
            f"{label} ajustado de {normalized} para {MAX_PAGE_SIZE} por limite da API."
        )
        return MAX_PAGE_SIZE

    return normalized


def ensure_directory(dir_path):
    os.makedirs(dir_path, exist_ok=True)


def get_inventory_cache_paths(cache_dir):
    normalized_dir = os.path.abspath(cache_dir)
    return {
        "directory": normalized_dir,
        "endpoints": os.path.join(normalized_dir, INVENTORY_CACHE_ENDPOINTS_FILE),
        "attributes": os.path.join(normalized_dir, INVENTORY_CACHE_ATTRIBUTES_FILE),
        "metadata": os.path.join(normalized_dir, INVENTORY_CACHE_METADATA_FILE),
    }


def write_jsonl_records(file_path, records):
    with open(file_path, "w", encoding="utf-8") as output_file:
        for record in records:
            output_file.write(json.dumps(record) + "\n")


def read_jsonl_records(file_path):
    records = []

    if not os.path.exists(file_path):
        return records

    with open(file_path, "r", encoding="utf-8") as input_file:
        for raw_line in input_file:
            line = raw_line.strip()
            if not line:
                continue

            records.append(json.loads(line))

    return records


def get_last_endpoint_created_at(endpoints=None, metadata=None):
    endpoint_created_at_values = [
        endpoint.get(ENDPOINT_PARTITION_FIELD)
        for endpoint in (endpoints or [])
        if isinstance(endpoint.get(ENDPOINT_PARTITION_FIELD), int)
    ]
    if endpoint_created_at_values:
        return max(endpoint_created_at_values)

    if isinstance((metadata or {}).get("lastEndpointCreatedAt"), int):
        return metadata["lastEndpointCreatedAt"]

    partition_end_values = [
        partition.get("end")
        for partition in ((metadata or {}).get("endpointPartitions") or [])
        if isinstance(partition.get("end"), int)
    ]
    if partition_end_values:
        return max(partition_end_values)

    return None


def is_inventory_snapshot_complete(metadata):
    if not metadata:
        return False

    return bool(
        metadata.get("endpointsComplete")
        and metadata.get("endpointAttributesComplete")
    )


def build_inventory_cache_metadata(
    base_url,
    endpoints,
    endpoint_attributes,
    partition_max_records,
    endpoint_partition_summaries,
    attribute_partition_summaries,
    mode,
    previous_metadata=None,
    incremental_from_endpoint_created_at=None,
    incremental_added_endpoints=0,
    incremental_added_endpoint_attributes=0,
):
    now_iso = datetime.now(UTC).isoformat()
    endpoints_complete = bool(endpoint_partition_summaries) and all(
        partition["complete"] for partition in endpoint_partition_summaries
    )
    attributes_complete = bool(attribute_partition_summaries) and all(
        partition["complete"] for partition in attribute_partition_summaries
    )

    metadata = {
        "createdAt": now_iso,
        "baseUrl": base_url,
        "endpointsCount": len(endpoints),
        "endpointAttributesCount": len(endpoint_attributes),
        "inventoryRefreshMode": mode,
        "partitionMaxRecords": partition_max_records,
        "endpointPartitionField": ENDPOINT_PARTITION_FIELD,
        "endpointAttributePartitionField": ATTRIBUTE_PARTITION_FIELD,
        "endpointsComplete": endpoints_complete,
        "endpointAttributesComplete": attributes_complete,
        "endpointPartitions": endpoint_partition_summaries,
        "endpointAttributePartitions": attribute_partition_summaries,
        "lastEndpointCreatedAt": get_last_endpoint_created_at(
            endpoints,
            previous_metadata,
        ),
    }

    if previous_metadata:
        metadata["lastFullRefreshAt"] = previous_metadata.get(
            "lastFullRefreshAt"
        ) or previous_metadata.get("createdAt")

    if mode == "partitioned":
        metadata["lastFullRefreshAt"] = now_iso
    else:
        metadata["lastIncrementalRefreshAt"] = now_iso
        metadata["incrementalFromEndpointCreatedAt"] = (
            incremental_from_endpoint_created_at
        )
        metadata["incrementalAddedEndpointsCount"] = int(incremental_added_endpoints)
        metadata["incrementalAddedEndpointAttributesCount"] = int(
            incremental_added_endpoint_attributes
        )

    return metadata


def merge_endpoint_records(existing_endpoints, new_endpoints):
    merged_by_id = {}
    records_without_id = []

    for endpoint in existing_endpoints + new_endpoints:
        endpoint_id = endpoint.get("endpointId")
        if endpoint_id is None:
            records_without_id.append(endpoint)
            continue

        merged_by_id[endpoint_id] = endpoint

    merged_endpoints = list(merged_by_id.values()) + records_without_id
    merged_endpoints.sort(
        key=lambda endpoint: (
            int(endpoint.get(ENDPOINT_PARTITION_FIELD) or 0),
            int(endpoint.get("endpointId") or 0),
            clean_text(endpoint.get("endpointName", "")),
        )
    )
    return merged_endpoints


def get_endpoint_attribute_record_key(item):
    endpoint = item.get("endpointAttributesEndpoint", {})
    attribute = item.get("endpointAttributesAttribute", {})
    attribute_source = attribute.get("attributeAttributeSource", {})

    endpoint_id = endpoint.get("endpointId")
    endpoint_name = clean_text(endpoint.get("endpointName", ""))
    source_name = clean_text(attribute_source.get("attributeSourceName", "")).casefold()

    if endpoint_id is not None and source_name:
        return ("endpoint_id", int(endpoint_id), source_name)

    if endpoint_name and source_name:
        return ("endpoint_name", endpoint_name, source_name)

    return json.dumps(item, sort_keys=True, ensure_ascii=False)


def merge_endpoint_attribute_records(existing_attributes, new_attributes):
    merged_by_key = {}

    for item in existing_attributes + new_attributes:
        merged_by_key[get_endpoint_attribute_record_key(item)] = item

    return list(merged_by_key.values())


def save_inventory_cache(cache_dir, endpoints, endpoint_attributes, metadata):
    cache_paths = get_inventory_cache_paths(cache_dir)
    ensure_directory(cache_paths["directory"])

    write_jsonl_records(cache_paths["endpoints"], endpoints)
    write_jsonl_records(cache_paths["attributes"], endpoint_attributes)

    with open(cache_paths["metadata"], "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, ensure_ascii=False, indent=2)

    return cache_paths


def load_inventory_cache(cache_dir):
    cache_paths = get_inventory_cache_paths(cache_dir)
    metadata = {}

    if os.path.exists(cache_paths["metadata"]):
        with open(cache_paths["metadata"], "r", encoding="utf-8") as metadata_file:
            metadata = json.load(metadata_file)

    endpoints = read_jsonl_records(cache_paths["endpoints"])
    endpoint_attributes = read_jsonl_records(cache_paths["attributes"])

    return endpoints, endpoint_attributes, metadata, cache_paths


def inventory_cache_exists(cache_dir):
    cache_paths = get_inventory_cache_paths(cache_dir)
    return (
        os.path.exists(cache_paths["metadata"])
        and os.path.exists(cache_paths["endpoints"])
        and os.path.exists(cache_paths["attributes"])
    )


def refresh_inventory_cache(
    session,
    headers,
    base_url,
    endpoint_page_size,
    attribute_page_size,
    cache_dir,
    partition_max_records,
):
    print(f"Atualizando cache local do inventário em {os.path.abspath(cache_dir)}...")

    endpoint_url = f"{base_url}/vicarius-external-data-api/endpoint/search"
    endpoint_min_created_at, endpoint_max_created_at = discover_numeric_bounds(
        session,
        headers,
        endpoint_url,
        ENDPOINT_PARTITION_FIELD,
        include_fields=f"endpointId,{ENDPOINT_PARTITION_FIELD}",
    )

    endpoint_partitions = build_numeric_partitions(
        session,
        headers,
        endpoint_url,
        ENDPOINT_PARTITION_FIELD,
        endpoint_min_created_at,
        endpoint_max_created_at,
        partition_max_records,
    )

    endpoints, endpoint_partition_summaries = fetch_partitioned_pages(
        session,
        headers,
        endpoint_url,
        endpoint_page_size,
        page_delay=ENDPOINT_PAGE_DELAY,
        label="endpoints",
        partitions=endpoint_partitions,
        include_fields=ENDPOINT_INCLUDE_FIELDS,
        max_records=partition_max_records,
    )

    print(
        f"Aguardando {ATTRIBUTE_WARMUP_DELAY:.0f}s antes de consultar atributos do inventário..."
    )
    time.sleep(ATTRIBUTE_WARMUP_DELAY)

    endpoint_ids = sorted(
        endpoint.get("endpointId")
        for endpoint in endpoints
        if isinstance(endpoint.get("endpointId"), int)
    )

    attribute_partitions = []
    attribute_url = f"{base_url}/vicarius-external-data-api/endpointAttributes/search"
    attribute_partition_max_records = min(
        int(partition_max_records),
        ATTRIBUTE_FETCH_PARTITION_MAX_RECORDS,
    )
    if endpoint_ids:
        attribute_partitions = build_endpoint_id_partitions(
            endpoint_ids,
            ATTRIBUTE_ENDPOINT_IDS_PER_PARTITION,
        )

    endpoint_attributes, attribute_partition_summaries = fetch_partitioned_pages(
        session,
        headers,
        attribute_url,
        attribute_page_size,
        page_delay=ATTRIBUTE_PAGE_DELAY,
        label="atributos",
        partitions=attribute_partitions,
        include_fields=ENDPOINT_ATTRIBUTE_INCLUDE_FIELDS,
        max_records=attribute_partition_max_records,
    )

    metadata = build_inventory_cache_metadata(
        base_url,
        endpoints,
        endpoint_attributes,
        partition_max_records,
        endpoint_partition_summaries,
        attribute_partition_summaries,
        mode="partitioned",
    )

    save_inventory_cache(cache_dir, endpoints, endpoint_attributes, metadata)
    print(
        "Cache local atualizado: "
        f"{len(endpoints)} endpoints e {len(endpoint_attributes)} atributo(s)."
    )

    return endpoints, endpoint_attributes, metadata


def refresh_inventory_cache_incremental(
    session,
    headers,
    base_url,
    endpoint_page_size,
    attribute_page_size,
    cache_dir,
    partition_max_records,
):
    existing_endpoints, existing_endpoint_attributes, previous_metadata, _ = (
        load_inventory_cache(cache_dir)
    )

    if not is_inventory_snapshot_complete(previous_metadata):
        print(
            "Snapshot local ausente ou incompleto para incremental; executando refresh completo do inventário."
        )
        return refresh_inventory_cache(
            session,
            headers,
            base_url,
            endpoint_page_size,
            attribute_page_size,
            cache_dir,
            partition_max_records,
        )

    previous_base_url = clean_text(previous_metadata.get("baseUrl", "")).rstrip("/")
    if previous_base_url and previous_base_url != base_url:
        print(
            "Base URL do snapshot local difere da configuração atual; executando refresh completo do inventário."
        )
        return refresh_inventory_cache(
            session,
            headers,
            base_url,
            endpoint_page_size,
            attribute_page_size,
            cache_dir,
            partition_max_records,
        )

    last_endpoint_created_at = get_last_endpoint_created_at(
        existing_endpoints,
        previous_metadata,
    )
    if last_endpoint_created_at is None:
        print(
            "Snapshot local não informa o último endpointCreatedAt; executando refresh completo do inventário."
        )
        return refresh_inventory_cache(
            session,
            headers,
            base_url,
            endpoint_page_size,
            attribute_page_size,
            cache_dir,
            partition_max_records,
        )

    print(
        "Atualizando cache local do inventário incrementalmente em "
        f"{os.path.abspath(cache_dir)} a partir de endpointCreatedAt >= {last_endpoint_created_at}..."
    )

    endpoint_url = f"{base_url}/vicarius-external-data-api/endpoint/search"
    _, endpoint_max_created_at = discover_numeric_bounds(
        session,
        headers,
        endpoint_url,
        ENDPOINT_PARTITION_FIELD,
        include_fields=f"endpointId,{ENDPOINT_PARTITION_FIELD}",
    )

    if (
        endpoint_max_created_at is None
        or int(endpoint_max_created_at) <= int(last_endpoint_created_at)
    ):
        print("Nenhum novo endpoint encontrado para refresh incremental do cache.")
        metadata = build_inventory_cache_metadata(
            base_url,
            existing_endpoints,
            existing_endpoint_attributes,
            partition_max_records,
            previous_metadata.get("endpointPartitions") or [],
            previous_metadata.get("endpointAttributePartitions") or [],
            mode="incremental",
            previous_metadata=previous_metadata,
            incremental_from_endpoint_created_at=last_endpoint_created_at,
            incremental_added_endpoints=0,
            incremental_added_endpoint_attributes=0,
        )
        save_inventory_cache(
            cache_dir,
            existing_endpoints,
            existing_endpoint_attributes,
            metadata,
        )
        return existing_endpoints, existing_endpoint_attributes, metadata

    endpoint_partitions = build_numeric_partitions(
        session,
        headers,
        endpoint_url,
        ENDPOINT_PARTITION_FIELD,
        last_endpoint_created_at,
        endpoint_max_created_at,
        partition_max_records,
    )

    new_endpoints, endpoint_partition_summaries = fetch_partitioned_pages(
        session,
        headers,
        endpoint_url,
        endpoint_page_size,
        page_delay=ENDPOINT_PAGE_DELAY,
        label="endpoints incrementais",
        partitions=endpoint_partitions,
        include_fields=ENDPOINT_INCLUDE_FIELDS,
        max_records=partition_max_records,
    )

    if not new_endpoints:
        print("Nenhum endpoint novo retornado pelo refresh incremental.")
        metadata = build_inventory_cache_metadata(
            base_url,
            existing_endpoints,
            existing_endpoint_attributes,
            partition_max_records,
            endpoint_partition_summaries,
            previous_metadata.get("endpointAttributePartitions") or [],
            mode="incremental",
            previous_metadata=previous_metadata,
            incremental_from_endpoint_created_at=last_endpoint_created_at,
            incremental_added_endpoints=0,
            incremental_added_endpoint_attributes=0,
        )
        save_inventory_cache(
            cache_dir,
            existing_endpoints,
            existing_endpoint_attributes,
            metadata,
        )
        return existing_endpoints, existing_endpoint_attributes, metadata

    print(
        f"Aguardando {ATTRIBUTE_WARMUP_DELAY:.0f}s antes de consultar atributos dos novos endpoints..."
    )
    time.sleep(ATTRIBUTE_WARMUP_DELAY)

    new_endpoint_ids = sorted(
        {
            endpoint.get("endpointId")
            for endpoint in new_endpoints
            if isinstance(endpoint.get("endpointId"), int)
        }
    )
    attribute_partitions = build_endpoint_id_partitions(
        new_endpoint_ids,
        ATTRIBUTE_ENDPOINT_IDS_PER_PARTITION,
    )
    attribute_url = f"{base_url}/vicarius-external-data-api/endpointAttributes/search"
    attribute_partition_max_records = min(
        int(partition_max_records),
        ATTRIBUTE_FETCH_PARTITION_MAX_RECORDS,
    )
    new_endpoint_attributes, attribute_partition_summaries = fetch_partitioned_pages(
        session,
        headers,
        attribute_url,
        attribute_page_size,
        page_delay=ATTRIBUTE_PAGE_DELAY,
        label="atributos incrementais",
        partitions=attribute_partitions,
        include_fields=ENDPOINT_ATTRIBUTE_INCLUDE_FIELDS,
        max_records=attribute_partition_max_records,
    )

    merged_endpoints = merge_endpoint_records(existing_endpoints, new_endpoints)
    merged_endpoint_attributes = merge_endpoint_attribute_records(
        existing_endpoint_attributes,
        new_endpoint_attributes,
    )
    metadata = build_inventory_cache_metadata(
        base_url,
        merged_endpoints,
        merged_endpoint_attributes,
        partition_max_records,
        endpoint_partition_summaries,
        attribute_partition_summaries,
        mode="incremental",
        previous_metadata=previous_metadata,
        incremental_from_endpoint_created_at=last_endpoint_created_at,
        incremental_added_endpoints=len(new_endpoints),
        incremental_added_endpoint_attributes=len(new_endpoint_attributes),
    )

    save_inventory_cache(
        cache_dir,
        merged_endpoints,
        merged_endpoint_attributes,
        metadata,
    )
    print(
        "Cache local atualizado incrementalmente: "
        f"+{len(new_endpoints)} endpoint(s), +{len(new_endpoint_attributes)} atributo(s). "
        f"Total: {len(merged_endpoints)} endpoints e {len(merged_endpoint_attributes)} atributo(s)."
    )

    return merged_endpoints, merged_endpoint_attributes, metadata


def refresh_inventory_cache_operation(
    session,
    headers,
    base_url,
    endpoint_page_size,
    attribute_page_size,
    cache_dir=DEFAULT_INVENTORY_CACHE_DIR,
    partition_max_records=DEFAULT_INVENTORY_PARTITION_MAX_RECORDS,
):
    cache_exists = inventory_cache_exists(cache_dir)

    if cache_exists:
        print(
            "Cache local existente detectado; tentando atualizar o inventário a partir do snapshot atual."
        )
        return refresh_inventory_cache_incremental(
            session,
            headers,
            base_url,
            endpoint_page_size,
            attribute_page_size,
            cache_dir,
            partition_max_records,
        )

    print(
        "Cache local inexistente; executando download completo do inventário."
    )
    return refresh_inventory_cache(
        session,
        headers,
        base_url,
        endpoint_page_size,
        attribute_page_size,
        cache_dir,
        partition_max_records,
    )


def create_lookup_container():
    return {
        "by_id": {},
        "by_name": {},
    }


def normalize_lookup_name(name):
    return clean_text(name)


def register_lookup_record(lookup, record, endpoint_id=None, endpoint_name=None):
    endpoint_id = endpoint_id if endpoint_id is not None else record.get("endpointId")
    endpoint_name = endpoint_name if endpoint_name is not None else record.get(
        "endpointName"
    )

    if endpoint_id is not None:
        lookup["by_id"][endpoint_id] = record

    normalized_name = normalize_lookup_name(endpoint_name)
    if normalized_name:
        lookup["by_name"][normalized_name] = record


def count_lookup_entries(lookup):
    if not lookup:
        return 0

    if "by_id" in lookup and "by_name" in lookup:
        return max(len(lookup["by_id"]), len(lookup["by_name"]))

    return len(lookup)


def find_lookup_record(lookup, endpoint_id=None, endpoint_name=""):
    if not lookup:
        return None

    if "by_id" not in lookup or "by_name" not in lookup:
        if endpoint_id is not None:
            return lookup.get(endpoint_id)
        return None

    if endpoint_id is not None and endpoint_id in lookup["by_id"]:
        return lookup["by_id"][endpoint_id]

    normalized_name = normalize_lookup_name(endpoint_name)
    if normalized_name:
        return lookup["by_name"].get(normalized_name)

    return None


def create_coverage_tracker(fieldnames):
    return {
        fieldname: {
            "filled": 0,
            "empty": 0,
        }
        for fieldname in fieldnames
    }


def is_filled_value(value):
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    return True


def update_coverage_tracker(coverage_tracker, row):
    for fieldname, stats in coverage_tracker.items():
        if is_filled_value(row.get(fieldname)):
            stats["filled"] += 1
        else:
            stats["empty"] += 1


def build_coverage_summary(coverage_tracker, total_rows):
    summary = []

    for fieldname, stats in coverage_tracker.items():
        filled = stats["filled"]
        empty = stats["empty"]
        percent = 0.0 if total_rows == 0 else (filled / total_rows) * 100
        summary.append(
            {
                "field": fieldname,
                "filled": filled,
                "empty": empty,
                "percent": percent,
            }
        )

    return summary


def print_coverage_summary(coverage_tracker, total_rows):
    if not coverage_tracker:
        print("Cobertura por coluna: nenhuma linha exportada.")
        return

    print("\nCobertura por coluna:")

    for item in build_coverage_summary(coverage_tracker, total_rows):
        print(
            f"- {item['field']}: {item['filled']}/{total_rows} preenchidos "
            f"({item['percent']:.1f}%), {item['empty']} vazios"
        )


def get_external_reference_value(endpoint_info, *source_names):
    expected = {name.casefold() for name in source_names}

    for item in endpoint_info.get("endpointEndpointExternalReferences", []) or []:
        external_reference = item.get(
            "endpointExternalReferencesExternalReference",
            {},
        )
        source = (
            external_reference.get("externalReferenceExternalReferenceSource", {})
            .get("externalReferenceSourceName", "")
        )

        if source.casefold() in expected:
            return external_reference.get("externalReferenceExternalId", "")

    return ""


def collect_endpoint_lookup(endpoints):
    lookup = create_lookup_container()

    for endpoint in endpoints:
        register_lookup_record(lookup, endpoint)

    return lookup


def collect_endpoint_attribute_lookup(endpoint_attributes):
    lookup = create_lookup_container()

    for item in endpoint_attributes:
        endpoint = item.get("endpointAttributesEndpoint", {})
        attribute = item.get("endpointAttributesAttribute", {})
        attribute_source = attribute.get("attributeAttributeSource", {})

        endpoint_id = endpoint.get("endpointId")
        source_name = clean_text(attribute_source.get("attributeSourceName"))
        value = clean_text(attribute.get("attributeExternalId"))

        if endpoint_id is None or not source_name or not value:
            continue

        if source_name.casefold() not in RELEVANT_ATTRIBUTE_SOURCES:
            continue

        endpoint_name = endpoint.get("endpointName")
        endpoint_bucket = find_lookup_record(lookup, endpoint_id, endpoint_name)
        if endpoint_bucket is None:
            endpoint_bucket = {}
            register_lookup_record(
                lookup,
                endpoint_bucket,
                endpoint_id=endpoint_id,
                endpoint_name=endpoint_name,
            )

        endpoint_bucket[source_name.casefold()] = value

    return lookup


def build_operating_system_lookup_key(publisher_id=None, operating_system_id=None):
    if publisher_id in (None, "") or operating_system_id in (None, ""):
        return ""

    return f"{clean_text(publisher_id)}:{clean_text(operating_system_id)}"


def collect_operating_system_lookup(operating_systems):
    lookup = {}

    for item in operating_systems:
        key = build_operating_system_lookup_key(
            item.get("publisherId"),
            item.get("operatingSystemId"),
        )
        if not key:
            continue

        operating_system_name = clean_text(
            (
                item.get(
                    "organizationPublisherOperatingSystemsOperatingSystem",
                    {},
                )
            ).get("operatingSystemName")
        )
        if not operating_system_name:
            continue

        lookup[key] = {
            "publisherId": item.get("publisherId"),
            "operatingSystemId": item.get("operatingSystemId"),
            "operatingSystemName": operating_system_name,
        }

    return lookup


def fetch_operating_system_lookup(session, headers, base_url, page_size):
    operating_systems = fetch_all_pages(
        session,
        headers,
        f"{base_url}/vicarius-external-data-api/organizationPublisherOperatingSystems/search",
        page_size,
        page_delay=ENDPOINT_PAGE_DELAY,
        label="catálogo de sistemas operacionais",
        extra_params={
            "q": "publisherId>0;operatingSystemId>0",
            "includeFields": OPERATING_SYSTEM_INCLUDE_FIELDS,
        },
    )

    return collect_operating_system_lookup(operating_systems)


def build_partition_record(field_name, range_start, range_end, base_query="", count=None):
    return {
        "field": field_name,
        "start": int(range_start),
        "end": int(range_end),
        "count": int(count) if isinstance(count, int) else None,
        "query": build_query(
            base_query,
            build_numeric_range_query(field_name, range_start, range_end),
        ),
    }


def build_incident_partitions(
    session,
    headers,
    base_url,
    partition_max_records,
    incident_query,
):
    incident_url = f"{base_url}/vicarius-external-data-api/incidentEvent/filter"

    incident_min_created_at_nano, incident_max_created_at_nano = discover_numeric_bounds(
        session,
        headers,
        incident_url,
        INCIDENT_PARTITION_FIELD,
        q=incident_query,
    )

    if incident_min_created_at_nano is None or incident_max_created_at_nano is None:
        return []

    partition_count = max(1, MAX_INITIAL_INCIDENT_PARTITIONS)
    range_width = max(
        1,
        math.ceil(
            (int(incident_max_created_at_nano) - int(incident_min_created_at_nano) + 1)
            / partition_count
        ),
    )

    partitions = []
    current_start = int(incident_min_created_at_nano)

    while current_start <= int(incident_max_created_at_nano):
        current_end = min(
            int(incident_max_created_at_nano),
            current_start + range_width - 1,
        )
        partitions.append(
            build_partition_record(
                INCIDENT_PARTITION_FIELD,
                current_start,
                current_end,
                base_query=incident_query,
            )
        )
        current_start = current_end + 1

    return partitions


def split_partition(partition, base_query=""):
    range_start = int(partition["start"])
    range_end = int(partition["end"])

    if range_start >= range_end:
        return []

    midpoint = (range_start + range_end) // 2
    if midpoint < range_start or midpoint >= range_end:
        return []

    return [
        build_partition_record(
            partition["field"],
            range_start,
            midpoint,
            base_query=base_query,
        ),
        build_partition_record(
            partition["field"],
            midpoint + 1,
            range_end,
            base_query=base_query,
        ),
    ]


def fetch_incident_partition_events(
    session,
    headers,
    incident_url,
    page_size,
    partition,
):
    offset = 0
    pages = 0
    events = []

    while True:
        payload, status_code = request_json(
            session,
            incident_url,
            headers,
            params={
                "from": offset,
                "size": page_size,
                "q": partition["query"],
                "sort": f"+{INCIDENT_PARTITION_FIELD}",
            },
        )

        if status_code == 400:
            result = payload.get("serverResponseResult", {})
            if result.get("serverResponseResultCode") == "PARAMETER_VALUE_EXCEEDED_LIMIT":
                return [], False, True

            return events, False, False

        if status_code != 200:
            return events, False, False

        page_items = payload.get("serverResponseObject", [])
        if not page_items:
            break

        events.extend(page_items)
        pages += 1

        if pages == 1 or pages % 5 == 0:
            print(
                f"  incidentes partição [{partition['start']}, {partition['end']}]: "
                f"página {pages}, acumulado {len(events)}"
            )

        if pages % INCIDENT_PARTITION_COOLDOWN_EVERY == 0 and len(page_items) == page_size:
            time.sleep(INCIDENT_PARTITION_COOLDOWN_SECONDS)

        if pages >= INCIDENT_MAX_SAFE_PAGES and len(page_items) == page_size:
            print(
                f"  incidentes partição [{partition['start']}, {partition['end']}]: "
                f"atingiu {pages * page_size} registro(s) sem encerrar; refinando antes do limite de paginação da API..."
            )
            return events, False, True

        if len(page_items) < page_size:
            break

        offset += page_size
        time.sleep(INCIDENT_PAGE_DELAY)

    return events, True, False


def fetch_partitioned_event_batches(
    session,
    headers,
    base_url,
    page_size,
    partition_max_records,
    incident_query,
):
    incident_url = f"{base_url}/vicarius-external-data-api/incidentEvent/filter"
    incident_partitions = build_incident_partitions(
        session,
        headers,
        base_url,
        partition_max_records,
        incident_query,
    )

    pending_partitions = [(partition, 0) for partition in reversed(incident_partitions)]

    while pending_partitions:
        partition, depth = pending_partitions.pop()
        partition_label = (
            f"incidentes partição "
            f"[{partition['start']}, {partition['end']}]"
        )
        if partition.get("count") is not None:
            partition_label = f"{partition_label} (~{partition['count']} esperados)"

        print(
            f"Carregando {partition_label}..."
        )

        events, complete, overflow = fetch_incident_partition_events(
            session,
            headers,
            incident_url,
            page_size,
            partition,
        )

        if overflow and depth < MAX_PARTITION_REFINEMENT_DEPTH:
            refined_partitions = split_partition(
                partition,
                base_query=incident_query,
            )
            if refined_partitions:
                print(
                    f"Refinando {partition_label} após limite de paginação da API..."
                )
                for refined_partition in reversed(refined_partitions):
                    pending_partitions.append((refined_partition, depth + 1))
                continue

        if not complete:
            print(
                f"Aviso: {partition_label} retornou resultados parciais ou falhou antes do fim."
            )

        yield partition, events


def get_attribute_value(endpoint_attributes, exact_names=None, contains_terms=None):
    exact_names = exact_names or []
    contains_terms = contains_terms or []

    for name in exact_names:
        value = endpoint_attributes.get(name.casefold())
        if value:
            return value

    for source_name, value in endpoint_attributes.items():
        if any(term.casefold() in source_name for term in contains_terms):
            return value

    return ""


def get_matched_attribute_value(endpoint_attributes, attribute_name):
    matcher = ATTRIBUTE_MATCHERS[attribute_name]
    return get_attribute_value(
        endpoint_attributes,
        exact_names=matcher["exact_names"],
        contains_terms=matcher["contains_terms"],
    )


def get_endpoint_from_event(event):
    return (
        event.get("incidentEventEndpoint")
        or event.get("analyticsEventAuthenticatedModelAbs")
        or {}
    )


def get_vendor_product(event, endpoint_info):
    publisher_products = event.get("incidentEventOrganizationPublisherProducts") or {}
    publisher_operating_systems = (
        event.get("incidentEventOrganizationPublisherOperatingSystems") or {}
    )

    product_vendor = clean_text(
        (publisher_products.get("organizationPublisherProductsPublisher") or {}).get(
            "publisherName"
        )
        or (publisher_products.get("organizationPublisherProductsPublisher") or {}).get(
            "publisherId"
        )
    )
    product_name = clean_text(
        (publisher_products.get("organizationPublisherProductsProduct") or {}).get(
            "productName"
        )
    )

    os_vendor = clean_text(
        (
            publisher_operating_systems.get(
                "organizationPublisherOperatingSystemsPublisher",
                {},
            )
        ).get("publisherName")
        or (
            publisher_operating_systems.get(
                "organizationPublisherOperatingSystemsPublisher",
                {},
            )
        ).get("publisherId")
    )
    os_product = clean_text(
        (
            publisher_operating_systems.get(
                "organizationPublisherOperatingSystemsOperatingSystem",
                {},
            )
        ).get("operatingSystemName")
    )

    operating_system_name = clean_text(
        (endpoint_info.get("endpointOperatingSystem") or {}).get(
            "operatingSystemName"
        )
    )

    vendor = first_non_empty(product_vendor, os_vendor)
    product = first_non_empty(product_name, os_product, operating_system_name)

    return clean_text(vendor), clean_text(product)


def get_cve_name(event, vulnerability):
    incident_cve = event.get("incidentEventCve") or {}

    return clean_text(
        first_non_empty(
            (vulnerability.get("vulnerabilityExternalReference") or {}).get(
                "externalReferenceExternalId"
            ),
            incident_cve.get("cveName"),
            vulnerability.get("vulnerabilityName"),
        )
    )


def get_patch_id(event):
    patch_id = first_non_empty(
        event.get("patchId"),
        (event.get("incidentEventPatch") or {}).get("patchId"),
    )

    if patch_id in (0, "0"):
        return ""

    return clean_text(patch_id)


def get_event_id(event):
    return clean_text(
        first_non_empty(
            event.get("incidentEventId"),
            event.get("_id"),
        )
    )


def build_patch_link(patch_id):
    if not patch_id:
        return ""

    return f"https://patch.vicarius.io/{patch_id}"


def load_cached_inventory_lookups(
    cache_dir=DEFAULT_INVENTORY_CACHE_DIR,
):
    cache_exists = inventory_cache_exists(cache_dir)
    if not cache_exists:
        raise SystemExit(
            "Cache local do inventário não existe. Execute "
            f"`python {SCRIPT_RELATIVE_PATH} --refresh-inventory-cache` "
            "para baixá-lo antes de usar --use-inventory-cache."
        )

    print(
        "Usando cache local do inventário sem consultar endpoint/search nem endpointAttributes/search durante a exportação."
    )
    endpoints, endpoint_attributes, metadata, _ = load_inventory_cache(cache_dir)

    endpoint_lookup = collect_endpoint_lookup(endpoints)
    endpoint_attribute_lookup = collect_endpoint_attribute_lookup(endpoint_attributes)

    print(
        "Inventário carregado do cache local: "
        f"{count_lookup_entries(endpoint_lookup)} endpoint(s), "
        f"{count_lookup_entries(endpoint_attribute_lookup)} endpoint(s) com atributos úteis."
    )
    if metadata:
        print(
            "Snapshot do inventário criado em "
            f"{metadata.get('createdAt', 'desconhecido')}"
        )
        print(
            "Completude do snapshot: "
            f"endpoints={'sim' if metadata.get('endpointsComplete') else 'não'}, "
            f"atributos={'sim' if metadata.get('endpointAttributesComplete') else 'não'}"
        )

    return endpoint_lookup, endpoint_attribute_lookup


def initialize_enrichment_lookups(
    session,
    headers,
    base_url,
    endpoint_page_size,
):
    endpoint_lookup, endpoint_attribute_lookup = load_cached_inventory_lookups()
    print("Carregando catálogo de sistemas operacionais...")
    operating_system_lookup = fetch_operating_system_lookup(
        session,
        headers,
        base_url,
        endpoint_page_size,
    )
    print(
        "Catálogo de sistemas operacionais carregado: "
        f"{len(operating_system_lookup)} combinação(ões) publisherId/operatingSystemId."
    )
    return endpoint_lookup, endpoint_attribute_lookup, operating_system_lookup


def export_incidents_with_cache(
    args,
    session,
    headers,
    base_url,
    incident_page_size,
    endpoint_page_size,
):
    total = 0
    processed_pages = 0
    run_started_at = time.monotonic()

    from_date, to_date = resolve_incident_date_range(args)
    incident_query = build_incident_filter_query(from_date, to_date)
    print(
        "Filtro temporal de incidentes: "
        f"from={from_date.isoformat()}; to={to_date.isoformat()}"
    )

    (
        endpoint_lookup,
        endpoint_attribute_lookup,
        operating_system_lookup,
    ) = initialize_enrichment_lookups(
        session,
        headers,
        base_url,
        endpoint_page_size,
    )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csv_file, open(
        OUTPUT_JSONL,
        "w",
        encoding="utf-8",
    ) as jsonl:
        csv_writer = None
        coverage_tracker = None

        event_batches = fetch_partitioned_event_batches(
            session,
            headers,
            base_url,
            incident_page_size,
            DEFAULT_INCIDENT_PARTITION_MAX_RECORDS,
            incident_query,
        )

        for _, events in event_batches:
            rows = process_events(
                events,
                endpoint_lookup,
                endpoint_attribute_lookup,
                operating_system_lookup,
            )

            for row in rows:
                jsonl.write(json.dumps(row) + "\n")

                if csv_writer is None:
                    csv_writer = csv.DictWriter(csv_file, fieldnames=row.keys())
                    csv_writer.writeheader()
                    coverage_tracker = create_coverage_tracker(row.keys())

                csv_writer.writerow(row)
                update_coverage_tracker(coverage_tracker, row)
                total += 1

            processed_pages += max(
                1,
                (len(events) + incident_page_size - 1) // incident_page_size,
            )

            elapsed = format_duration(time.monotonic() - run_started_at)
            print(
                "Progresso geral: "
                f"{total} vulnerabilidade(s) exportada(s), "
                f"{processed_pages} página(s) processada(s), "
                f"tempo decorrido {elapsed}."
            )

    print("\nColeta finalizada")
    print("Total vulnerabilidades:", total)
    print("Páginas processadas:", processed_pages)
    print("JSONL:", OUTPUT_JSONL)
    print("CSV:", OUTPUT_CSV)
    print_coverage_summary(coverage_tracker or {}, total)


def normalize(
    event,
    endpoint_lookup=None,
    endpoint_attribute_lookup=None,
    operating_system_lookup=None,
):
    endpoint_lookup = endpoint_lookup or {}
    endpoint_attribute_lookup = endpoint_attribute_lookup or {}
    operating_system_lookup = operating_system_lookup or {}

    vulnerability = event.get("incidentEventVulnerability", {})
    endpoint = get_endpoint_from_event(event)
    endpoint_id = endpoint.get("endpointId")
    endpoint_name = endpoint.get("endpointName", "")
    endpoint_info = find_lookup_record(endpoint_lookup, endpoint_id, endpoint_name) or endpoint
    endpoint_attributes = (
        find_lookup_record(endpoint_attribute_lookup, endpoint_id, endpoint_name) or {}
    )
    organization = endpoint_info.get("endpointOrganization", {})
    publisher_operating_systems = (
        event.get("incidentEventOrganizationPublisherOperatingSystems") or {}
    )

    vendor, product = get_vendor_product(event, endpoint_info)
    cve_name = get_cve_name(event, vulnerability)

    operating_system_lookup_key = build_operating_system_lookup_key(
        first_non_empty(
            endpoint.get("operatingSystemPublisherId"),
            event.get("publisherId"),
        ),
        first_non_empty(
            endpoint.get("operatingSystemId"),
            event.get("operatingSystemId"),
        ),
    )
    operating_system_from_catalog = clean_text(
        (operating_system_lookup.get(operating_system_lookup_key) or {}).get(
            "operatingSystemName"
        )
    )

    operating_system = clean_text(
        first_non_empty(
            (endpoint_info.get("endpointOperatingSystem") or {}).get(
                "operatingSystemName"
            ),
            (
                publisher_operating_systems.get(
                    "organizationPublisherOperatingSystemsOperatingSystem",
                    {},
                )
            ).get("operatingSystemName"),
            operating_system_from_catalog,
        )
    )

    operating_system_version = clean_text(
        first_non_empty(
            get_matched_attribute_value(endpoint_attributes, "operating_system_version"),
            endpoint.get("operatingSystemVersion"),
        )
    )

    internal_ip = normalize_ip(
        first_non_empty(
            get_matched_attribute_value(endpoint_attributes, "internal_ip"),
            endpoint.get("endpointInternalIp"),
            endpoint.get("internalIp"),
        )
    )

    external_ip = normalize_ip(
        first_non_empty(
            get_matched_attribute_value(endpoint_attributes, "external_ip"),
            endpoint.get("endpointExternalIp"),
            endpoint.get("externalIp"),
        )
    )

    mac_address = clean_text(
        first_non_empty(
            get_external_reference_value(
                endpoint_info,
                "MAC Address ID",
                "MAC Address",
            ),
            get_matched_attribute_value(endpoint_attributes, "mac_address"),
            endpoint.get("endpointMacAddress"),
            endpoint.get("macAddress"),
        )
    )

    organizational_unit = clean_text(
        first_non_empty(
            get_matched_attribute_value(endpoint_attributes, "organizational_unit"),
            organization.get("organizationName"),
        )
    )

    score = vulnerability.get("vulnerabilityV3BaseScore")

    patch_id = get_patch_id(event)

    kev_raw = vulnerability.get("vulnerabilityCISARequiredAction")
    kev_val = ""
    if kev_raw:
        vid = clean_text(
            first_non_empty(
                vulnerability.get("vulnerabilityId"),
                event.get("incidentEventVulnerabilityId"),
                event.get("vulnerabilityId"),
            )
        )
        if not vid:
            vid = "N/A"
            
        cves = [c.strip() for c in cve_name.replace(',', ' ').split() if c.strip()]
        if cves:
            kev_val = "|".join(f"[{vid}] {c}" for c in cves)
        else:
            kev_val = f"[{vid}] {cve_name}"

    return {
        "CVE Name": cve_name,
        "Product": product,
        "Vendor": vendor,
        "CVE Severity": severity(score),
        "CVSS 3 Base Score": score,
        "CVSS Vector": clean_text(vulnerability.get("vulnerabilityV3Vector", "")),
        "CVE Publish Date": convert_date(
            vulnerability.get("vulnerabilityPublishedAt")
        ),
        "Vendor Patch Link": build_patch_link(patch_id),
        "Vulnerability Summary": clean_text(
            vulnerability.get("vulnerabilitySummary", "")
        ),
        "KEV": kev_val,
        "Endpoint": clean_text(endpoint_info.get("endpointName", "")),
        "Endpoint ID": clean_text(endpoint_info.get("endpointId", "")),
        "Operating System": operating_system,
        "Operating System Version": operating_system_version,
        "Internal IP Address": internal_ip,
        "External IP Address": external_ip,
        "MAC Address": mac_address,
        "Organizational Unit": organizational_unit,
        "DetectionDate": convert_date(event.get("analyticsEventCreatedAt")),
        "Last Seen": convert_date(event.get("analyticsEventUpdatedAt")),
        "SnapshotDate": datetime.now(UTC).strftime("%Y-%m-%d"),
        "Patch ID": patch_id,
        "Incident Event Type": clean_text(
            event.get("incidentEventIncidentEventType", "")
        ),
        "Event ID": get_event_id(event),
    }


def process_events(
    events,
    endpoint_lookup=None,
    endpoint_attribute_lookup=None,
    operating_system_lookup=None,
):
    return [
        normalize(
            event,
            endpoint_lookup,
            endpoint_attribute_lookup,
            operating_system_lookup,
        )
        for event in events
        if event.get("incidentEventIncidentEventType") == "DetectedVulnerability"
    ]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Mantém o cache do inventário Vicarius e exporta incidentes usando o cache local dentro de um intervalo explícito de datas.",
    )
    parser.add_argument(
        "--from-date",
        help="Data/hora inicial (ISO 8601, UTC se sem fuso) para exportação usando o cache local. Ex.: 2026-03-22 ou 2026-03-22T14:30:00.",
    )
    parser.add_argument(
        "--to-date",
        help="Data/hora final (ISO 8601, UTC se sem fuso) para exportação usando o cache local. Ex.: 2026-03-22 ou 2026-03-22T23:59:59.",
    )
    parser.add_argument(
        "--refresh-inventory-cache",
        action="store_true",
        help="Operação exclusiva de cache: se o snapshot local existir, tenta atualizá-lo incrementalmente; se não existir, baixa o inventário completo e encerra.",
    )
    parser.add_argument(
        "--use-inventory-cache",
        action="store_true",
        help="Usa o snapshot local do inventário para enriquecimento, sem consultar o inventário durante a exportação.",
    )
    return parser.parse_args()


def main():
    configure_console_output()
    args = parse_args()
    load_env_file(DEFAULT_ENV_FILE)
    mode = validate_execution_mode(args)
    api_key, base_url = get_api_configuration()
    runtime_settings = get_runtime_settings()
    headers = build_headers(api_key)

    with requests.Session() as session:
        if mode == "refresh-cache":
            refresh_inventory_cache_operation(
                session,
                headers,
                base_url,
                runtime_settings["endpoint_page_size"],
                runtime_settings["attribute_page_size"],
            )
            print("\nOperação de cache finalizada")
            return

        export_incidents_with_cache(
            args,
            session,
            headers,
            base_url,
            runtime_settings["incident_page_size"],
            runtime_settings["endpoint_page_size"],
        )


if __name__ == "__main__":
    main()