import importlib.util
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from datetime import UTC, datetime, timedelta


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "export-inventory-vulnerabilities.py"
SPEC = importlib.util.spec_from_file_location("export_inventory_vulnerabilities", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestExportInventoryVulnerabilities(unittest.TestCase):
    def test_normalize_product_event_with_endpoint_enrichment(self):
        event = {
            "incidentEventIncidentEventType": "DetectedVulnerability",
            "_id": "event-123",
            "analyticsEventCreatedAt": 1717977600000,
            "analyticsEventUpdatedAt": 1718064000000,
            "incidentEventEndpoint": {
                "endpointId": 777827,
                "endpointName": "SRVRODC179",
                "endpointOrganization": {"organizationName": "atacadao"},
            },
            "incidentEventVulnerability": {
                "vulnerabilityExternalReference": {
                    "externalReferenceExternalId": "CVE-2022-36954"
                },
                "vulnerabilityV3BaseScore": 9.8,
                "vulnerabilityV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "vulnerabilityPublishedAt": 1658880000000,
                "vulnerabilitySummary": "Resumo da vulnerabilidade",
            },
            "incidentEventOrganizationPublisherProducts": {
                "organizationPublisherProductsPublisher": {
                    "publisherName": "Veritas"
                },
                "organizationPublisherProductsProduct": {
                    "productName": "NetBackup"
                },
            },
        }

        endpoint_lookup = {
            777827: {
                "endpointId": 777827,
                "endpointName": "SRVRODC179",
                "endpointOperatingSystem": {"operatingSystemName": "Windows Server"},
                "endpointOrganization": {"organizationName": "atacadao"},
                "endpointEndpointExternalReferences": [
                    {
                        "endpointExternalReferencesExternalReference": {
                            "externalReferenceExternalId": "AA:BB:CC:DD:EE:FF",
                            "externalReferenceExternalReferenceSource": {
                                "externalReferenceSourceName": "MAC Address ID"
                            },
                        }
                    }
                ],
            }
        }

        endpoint_attribute_lookup = {
            777827: {
                "internal ip address": "10.0.0.5",
                "external ip address": "34.95.244.185/32",
                "operating system version": "2019",
            }
        }

        row = MODULE.normalize(event, endpoint_lookup, endpoint_attribute_lookup)

        self.assertEqual(row["CVE Name"], "CVE-2022-36954")
        self.assertEqual(row["Product"], "NetBackup")
        self.assertEqual(row["Vendor"], "Veritas")
        self.assertEqual(row["Operating System"], "Windows Server")
        self.assertEqual(row["Operating System Version"], "2019")
        self.assertEqual(row["Internal IP Address"], "10.0.0.5")
        self.assertEqual(row["External IP Address"], "34.95.244.185")
        self.assertEqual(row["MAC Address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(row["Event ID"], "event-123")

    def test_normalize_operating_system_event_uses_os_product(self):
        event = {
            "incidentEventIncidentEventType": "DetectedVulnerability",
            "analyticsEventCreatedAt": 1717977600000,
            "analyticsEventUpdatedAt": 1718064000000,
            "patchId": 12345,
            "incidentEventEndpoint": {
                "endpointId": 42,
                "endpointName": "linux-host",
                "endpointOrganization": {"organizationName": "ops"},
            },
            "incidentEventVulnerability": {
                "vulnerabilityExternalReference": {
                    "externalReferenceExternalId": "CVE-2024-0001"
                },
                "vulnerabilityV3BaseScore": 7.5,
                "vulnerabilitySummary": "Kernel issue",
            },
            "incidentEventOrganizationPublisherOperatingSystems": {
                "organizationPublisherOperatingSystemsPublisher": {
                    "publisherName": "Oracle"
                },
                "organizationPublisherOperatingSystemsOperatingSystem": {
                    "operatingSystemName": "Oracle Linux 8"
                },
            },
        }

        endpoint_lookup = {
            42: {
                "endpointId": 42,
                "endpointName": "linux-host",
                "endpointOperatingSystem": {"operatingSystemName": "Oracle Linux 8"},
                "endpointOrganization": {"organizationName": "ops"},
                "endpointEndpointExternalReferences": [],
            }
        }

        row = MODULE.normalize(event, endpoint_lookup, {})

        self.assertEqual(row["Vendor"], "Oracle")
        self.assertEqual(row["Product"], "Oracle Linux 8")
        self.assertEqual(row["Operating System"], "Oracle Linux 8")
        self.assertEqual(row["Patch ID"], "12345")
        self.assertEqual(
            row["Vendor Patch Link"],
            "https://patch.vicarius.io/12345",
        )

    def test_process_events_filters_non_detected_events(self):
        events = [
            {"incidentEventIncidentEventType": "MitigatedVulnerability"},
            {
                "incidentEventIncidentEventType": "DetectedVulnerability",
                "incidentEventEndpoint": {"endpointId": 1, "endpointName": "asset"},
                "incidentEventVulnerability": {
                    "vulnerabilityExternalReference": {
                        "externalReferenceExternalId": "CVE-1"
                    },
                    "vulnerabilityV3BaseScore": 5.0,
                },
            },
        ]

        rows = MODULE.process_events(events, {}, {})

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["CVE Name"], "CVE-1")

    def test_build_coverage_summary_counts_filled_and_empty(self):
        tracker = MODULE.create_coverage_tracker(["A", "B", "C"])

        MODULE.update_coverage_tracker(tracker, {"A": "x", "B": "", "C": None})
        MODULE.update_coverage_tracker(tracker, {"A": "y", "B": "z", "C": 0})

        summary = MODULE.build_coverage_summary(tracker, 2)
        summary_by_field = {item["field"]: item for item in summary}

        self.assertEqual(summary_by_field["A"]["filled"], 2)
        self.assertEqual(summary_by_field["A"]["empty"], 0)
        self.assertEqual(summary_by_field["A"]["percent"], 100.0)
        self.assertEqual(summary_by_field["B"]["filled"], 1)
        self.assertEqual(summary_by_field["B"]["empty"], 1)
        self.assertEqual(summary_by_field["C"]["filled"], 1)
        self.assertEqual(summary_by_field["C"]["empty"], 1)

    def test_normalize_uses_lookup_by_endpoint_name_when_id_differs(self):
        event = {
            "incidentEventIncidentEventType": "DetectedVulnerability",
            "incidentEventEndpoint": {
                "endpointId": 777827,
                "endpointName": "SRVRODC179",
                "endpointOrganization": {"organizationName": "atacadao"},
            },
            "incidentEventVulnerability": {
                "vulnerabilityExternalReference": {
                    "externalReferenceExternalId": "CVE-2022-36954"
                },
                "vulnerabilityV3BaseScore": 5.0,
            },
            "incidentEventOrganizationPublisherProducts": {
                "organizationPublisherProductsPublisher": {
                    "publisherName": "Veritas"
                },
                "organizationPublisherProductsProduct": {
                    "productName": "NetBackup"
                },
            },
        }

        endpoint_lookup = MODULE.create_lookup_container()
        MODULE.register_lookup_record(
            endpoint_lookup,
            {
                "endpointId": 999999,
                "endpointName": "SRVRODC179",
                "endpointOperatingSystem": {"operatingSystemName": "Windows Server"},
                "endpointOrganization": {"organizationName": "atacadao"},
            },
        )

        endpoint_attribute_lookup = MODULE.create_lookup_container()
        MODULE.register_lookup_record(
            endpoint_attribute_lookup,
            {"internal ip address": "10.10.10.10"},
            endpoint_id=999999,
            endpoint_name="SRVRODC179",
        )

        row = MODULE.normalize(event, endpoint_lookup, endpoint_attribute_lookup)

        self.assertEqual(row["Operating System"], "Windows Server")
        self.assertEqual(row["Internal IP Address"], "10.10.10.10")

    def test_normalize_uses_operating_system_catalog_when_inventory_misses_endpoint(self):
        event = {
            "incidentEventIncidentEventType": "DetectedVulnerability",
            "incidentEventEndpoint": {
                "endpointId": 777827,
                "endpointName": "SRVRODC179",
                "operatingSystemId": 27811,
                "operatingSystemPublisherId": 20092,
                "endpointOrganization": {"organizationName": "atacadao"},
            },
            "publisherId": 21807,
            "operatingSystemId": None,
            "incidentEventVulnerability": {
                "vulnerabilityExternalReference": {
                    "externalReferenceExternalId": "CVE-2022-36954"
                },
                "vulnerabilityV3BaseScore": 9.8,
            },
            "incidentEventOrganizationPublisherProducts": {
                "organizationPublisherProductsPublisher": {
                    "publisherName": "Veritas"
                },
                "organizationPublisherProductsProduct": {
                    "productName": "NetBackup"
                },
            },
        }

        row = MODULE.normalize(
            event,
            {},
            {},
            {
                "20092:27811": {
                    "publisherId": 20092,
                    "operatingSystemId": 27811,
                    "operatingSystemName": "Windows Server 2022",
                }
            },
        )

        self.assertEqual(row["Operating System"], "Windows Server 2022")

    def test_collect_operating_system_lookup_maps_pairs_to_names(self):
        lookup = MODULE.collect_operating_system_lookup(
            [
                {
                    "publisherId": 20092,
                    "operatingSystemId": 28186,
                    "organizationPublisherOperatingSystemsOperatingSystem": {
                        "operatingSystemName": "Windows 11"
                    },
                }
            ]
        )

        self.assertEqual(
            lookup,
            {
                "20092:28186": {
                    "publisherId": 20092,
                    "operatingSystemId": 28186,
                    "operatingSystemName": "Windows 11",
                }
            },
        )

    def test_inventory_cache_roundtrip_preserves_records_and_metadata(self):
        created_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        endpoints = [
            {
                "endpointId": 101,
                "endpointName": "host-a",
                "endpointOperatingSystem": {"operatingSystemName": "Linux"},
            }
        ]
        endpoint_attributes = [
            {
                "endpointAttributesEndpoint": {
                    "endpointId": 101,
                    "endpointName": "host-a",
                },
                "endpointAttributesAttribute": {
                    "attributeExternalId": "10.0.0.1",
                    "attributeAttributeSource": {
                        "attributeSourceName": "Internal IP Address"
                    },
                },
            }
        ]
        metadata = {
            "createdAt": created_at,
            "baseUrl": "https://example.invalid",
            "endpointsCount": 1,
            "endpointAttributesCount": 1,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            MODULE.save_inventory_cache(
                temp_dir,
                endpoints,
                endpoint_attributes,
                metadata,
            )

            loaded_endpoints, loaded_attributes, loaded_metadata, cache_paths = (
                MODULE.load_inventory_cache(temp_dir)
            )

            self.assertEqual(loaded_endpoints, endpoints)
            self.assertEqual(loaded_attributes, endpoint_attributes)
            self.assertEqual(loaded_metadata, metadata)
            self.assertTrue(MODULE.inventory_cache_exists(temp_dir))
            self.assertTrue(pathlib.Path(cache_paths["endpoints"]).exists())
            self.assertTrue(pathlib.Path(cache_paths["attributes"]).exists())
            self.assertTrue(pathlib.Path(cache_paths["metadata"]).exists())

    def test_inventory_cache_exists_requires_all_snapshot_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_paths = MODULE.get_inventory_cache_paths(temp_dir)
            pathlib.Path(cache_paths["directory"]).mkdir(parents=True, exist_ok=True)
            pathlib.Path(cache_paths["endpoints"]).write_text(
                json.dumps({"endpointId": 1}) + "\n",
                encoding="utf-8",
            )
            pathlib.Path(cache_paths["attributes"]).write_text(
                json.dumps({"endpointAttributesEndpoint": {"endpointId": 1}}) + "\n",
                encoding="utf-8",
            )
            pathlib.Path(cache_paths["metadata"]).write_text(
                json.dumps({"createdAt": "2020-01-01T00:00:00+00:00"}),
                encoding="utf-8",
            )

            self.assertTrue(MODULE.inventory_cache_exists(temp_dir))

            pathlib.Path(cache_paths["attributes"]).unlink()

            self.assertFalse(MODULE.inventory_cache_exists(temp_dir))

    def test_get_last_endpoint_created_at_uses_endpoints_then_metadata(self):
        self.assertEqual(
            MODULE.get_last_endpoint_created_at(
                [
                    {"endpointId": 1, "endpointCreatedAt": 10},
                    {"endpointId": 2, "endpointCreatedAt": 20},
                ],
                {"lastEndpointCreatedAt": 5},
            ),
            20,
        )
        self.assertEqual(
            MODULE.get_last_endpoint_created_at(
                [],
                {
                    "endpointPartitions": [
                        {"start": 1, "end": 100},
                        {"start": 101, "end": 200},
                    ]
                },
            ),
            200,
        )

    def test_merge_endpoint_attribute_records_replaces_same_endpoint_source(self):
        existing = [
            {
                "endpointAttributesEndpoint": {
                    "endpointId": 10,
                    "endpointName": "host-a",
                },
                "endpointAttributesAttribute": {
                    "attributeExternalId": "10.0.0.1",
                    "attributeAttributeSource": {
                        "attributeSourceName": "Internal IP Address"
                    },
                },
            }
        ]
        updated = [
            {
                "endpointAttributesEndpoint": {
                    "endpointId": 10,
                    "endpointName": "host-a",
                },
                "endpointAttributesAttribute": {
                    "attributeExternalId": "10.0.0.2",
                    "attributeAttributeSource": {
                        "attributeSourceName": "Internal IP Address"
                    },
                },
            }
        ]

        merged = MODULE.merge_endpoint_attribute_records(existing, updated)

        self.assertEqual(len(merged), 1)
        self.assertEqual(
            merged[0]["endpointAttributesAttribute"]["attributeExternalId"],
            "10.0.0.2",
        )

    def test_build_numeric_range_query_uses_inclusive_bounds(self):
        self.assertEqual(
            MODULE.build_numeric_range_query("endpointId", 10, 20),
            "endpointId>9;endpointId<21",
        )
        self.assertEqual(
            MODULE.build_numeric_range_query("endpointCreatedAt", None, 30),
            "endpointCreatedAt<31",
        )

    def test_build_numeric_partitions_splits_until_threshold(self):
        calls = []

        def fake_fetch_total_count(
            session,
            headers,
            url,
            q="",
            include_fields=None,
            sort=None,
            extra_params=None,
            include_paging=True,
        ):
            calls.append(q)
            mapping = {
                "endpointId>0;endpointId<9": 8,
                "endpointId>0;endpointId<5": 4,
                "endpointId>4;endpointId<9": 4,
            }
            return mapping.get(q, 0), {}, 200

        original = MODULE.fetch_total_count
        MODULE.fetch_total_count = fake_fetch_total_count
        try:
            partitions = MODULE.build_numeric_partitions(
                None,
                None,
                "https://example.invalid/endpoint/search",
                "endpointId",
                1,
                8,
                4,
            )
        finally:
            MODULE.fetch_total_count = original

        self.assertEqual(
            partitions,
            [
                {
                    "field": "endpointId",
                    "start": 1,
                    "end": 4,
                    "count": 4,
                    "query": "endpointId>0;endpointId<5",
                },
                {
                    "field": "endpointId",
                    "start": 5,
                    "end": 8,
                    "count": 4,
                    "query": "endpointId>4;endpointId<9",
                },
            ],
        )
        self.assertGreaterEqual(len(calls), 3)

    def test_build_endpoint_id_partitions_chunks_real_endpoint_ids(self):
        partitions = MODULE.build_endpoint_id_partitions(
            [10, 11, 12, 20, 21],
            2,
        )

        self.assertEqual(
            partitions,
            [
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 10,
                    "end": 11,
                    "count": None,
                    "query": "endpointId>9;endpointId<12",
                    "_endpoint_ids": [10, 11],
                },
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 12,
                    "end": 20,
                    "count": None,
                    "query": "endpointId>11;endpointId<21",
                    "_endpoint_ids": [12, 20],
                },
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 21,
                    "end": 21,
                    "count": None,
                    "query": "endpointId>20;endpointId<22",
                    "_endpoint_ids": [21],
                },
            ],
        )

    def test_split_endpoint_id_partition_halves_partition_by_ids(self):
        partition = {
            "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
            "start": 100,
            "end": 140,
            "count": None,
            "query": "endpointId>99;endpointId<141",
            "_endpoint_ids": [100, 110, 130, 140],
        }

        self.assertEqual(
            MODULE.split_endpoint_id_partition(partition),
            [
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 100,
                    "end": 110,
                    "count": None,
                    "query": "endpointId>99;endpointId<111",
                    "_endpoint_ids": [100, 110],
                },
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 130,
                    "end": 140,
                    "count": None,
                    "query": "endpointId>129;endpointId<141",
                    "_endpoint_ids": [130, 140],
                },
            ],
        )

    def test_fetch_partitioned_pages_refines_incomplete_partition(self):
        original_fetch_all_pages = MODULE.fetch_all_pages
        original_build_numeric_partitions = MODULE.build_numeric_partitions

        def fake_fetch_all_pages(
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
            query = (extra_params or {}).get("q", "")
            if query == "endpointId>0;endpointId<9":
                result = [{"id": n} for n in range(4)]
                return (result, 200, False) if return_metadata else result
            if query == "endpointId>0;endpointId<5":
                result = [{"id": n} for n in range(4)]
                return (result, 200, False) if return_metadata else result
            if query == "endpointId>4;endpointId<9":
                result = [{"id": n} for n in range(4, 8)]
                return (result, 200, False) if return_metadata else result
            return ([], 200, False) if return_metadata else []

        def fake_build_numeric_partitions(
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
            if range_start == 1 and range_end == 8 and max_records == 4:
                return [
                    {
                        "field": "endpointId",
                        "start": 1,
                        "end": 4,
                        "count": 4,
                        "query": "endpointId>0;endpointId<5",
                    },
                    {
                        "field": "endpointId",
                        "start": 5,
                        "end": 8,
                        "count": 4,
                        "query": "endpointId>4;endpointId<9",
                    },
                ]

            return original_build_numeric_partitions(
                session,
                headers,
                url,
                field_name,
                range_start,
                range_end,
                max_records,
                base_query=base_query,
            )

        MODULE.fetch_all_pages = fake_fetch_all_pages
        MODULE.build_numeric_partitions = fake_build_numeric_partitions
        try:
            items, summaries = MODULE.fetch_partitioned_pages(
                None,
                None,
                "https://example.invalid/endpointAttributes/search",
                500,
                0,
                "atributos",
                [
                    {
                        "field": "endpointId",
                        "start": 1,
                        "end": 8,
                        "count": 8,
                        "query": "endpointId>0;endpointId<9",
                    }
                ],
                max_records=4,
            )
        finally:
            MODULE.fetch_all_pages = original_fetch_all_pages
            MODULE.build_numeric_partitions = original_build_numeric_partitions

        self.assertEqual(len(items), 8)
        self.assertEqual(len(summaries), 2)
        self.assertTrue(all(summary["complete"] for summary in summaries))

    def test_fetch_partitioned_pages_proactively_refines_oversized_partition(self):
        original_fetch_all_pages = MODULE.fetch_all_pages
        original_build_numeric_partitions = MODULE.build_numeric_partitions
        fetched_queries = []

        def fake_fetch_all_pages(
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
            query = (extra_params or {}).get("q", "")
            fetched_queries.append(query)
            if query == "endpointId>0;endpointId<5":
                result = [{"id": n} for n in range(4)]
                return (result, 200, False) if return_metadata else result
            if query == "endpointId>4;endpointId<9":
                result = [{"id": n} for n in range(4, 8)]
                return (result, 200, False) if return_metadata else result
            return ([], 200, False) if return_metadata else []

        def fake_build_numeric_partitions(
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
            if range_start == 1 and range_end == 8 and max_records == 4:
                return [
                    {
                        "field": "endpointId",
                        "start": 1,
                        "end": 4,
                        "count": 4,
                        "query": "endpointId>0;endpointId<5",
                    },
                    {
                        "field": "endpointId",
                        "start": 5,
                        "end": 8,
                        "count": 4,
                        "query": "endpointId>4;endpointId<9",
                    },
                ]

            return original_build_numeric_partitions(
                session,
                headers,
                url,
                field_name,
                range_start,
                range_end,
                max_records,
                base_query=base_query,
                count_url=count_url,
                count_extra_params=count_extra_params,
                count_include_paging=count_include_paging,
            )

        MODULE.fetch_all_pages = fake_fetch_all_pages
        MODULE.build_numeric_partitions = fake_build_numeric_partitions
        try:
            items, summaries = MODULE.fetch_partitioned_pages(
                None,
                None,
                "https://example.invalid/endpointAttributes/search",
                500,
                0,
                "atributos",
                [
                    {
                        "field": "endpointId",
                        "start": 1,
                        "end": 8,
                        "count": 8,
                        "query": "endpointId>0;endpointId<9",
                    }
                ],
                max_records=4,
            )
        finally:
            MODULE.fetch_all_pages = original_fetch_all_pages
            MODULE.build_numeric_partitions = original_build_numeric_partitions

        self.assertEqual(len(items), 8)
        self.assertEqual(len(summaries), 2)
        self.assertNotIn("endpointId>0;endpointId<9", fetched_queries)
        self.assertEqual(
            fetched_queries,
            ["endpointId>0;endpointId<5", "endpointId>4;endpointId<9"],
        )

    def test_is_partition_fetch_complete_accepts_one_record_drift(self):
        self.assertTrue(MODULE.is_partition_fetch_complete(10, 9))
        self.assertTrue(MODULE.is_partition_fetch_complete(10, 11))
        self.assertFalse(MODULE.is_partition_fetch_complete(10, 8))

    def test_resolve_incident_date_range_requires_closed_interval(self):
        args = SimpleNamespace(from_date="2026-03-20T10:00:00", to_date=None)

        with self.assertRaises(SystemExit) as ctx:
            MODULE.resolve_incident_date_range(args)

        self.assertIn("--use-inventory-cache com --from-date e --to-date", str(ctx.exception))

    def test_resolve_incident_date_range_rejects_inverted_interval(self):
        args = SimpleNamespace(
            from_date="2026-03-22T12:00:00",
            to_date="2026-03-21T12:00:00",
        )

        with self.assertRaises(SystemExit) as ctx:
            MODULE.resolve_incident_date_range(args)

        self.assertIn("--to-date deve ser maior ou igual", str(ctx.exception))

    def test_build_incident_filter_query_applies_lower_and_upper_bounds(self):
        query = MODULE.build_incident_filter_query(
            datetime(2026, 3, 20, 10, 0, 0, tzinfo=UTC),
            datetime(2026, 3, 21, 10, 0, 0, tzinfo=UTC),
        )

        self.assertIn(MODULE.DETECTED_VULNERABILITY_QUERY, query)
        self.assertIn("analyticsEventCreatedAtNano>", query)
        self.assertIn("analyticsEventCreatedAtNano<", query)

    def test_build_incident_partitions_uses_fixed_temporal_slices(self):
        original_discover_numeric_bounds = MODULE.discover_numeric_bounds
        original_max_initial_incident_partitions = MODULE.MAX_INITIAL_INCIDENT_PARTITIONS

        captured = {}

        def fake_discover_numeric_bounds(
            session,
            headers,
            url,
            field_name,
            include_fields=None,
            q="",
        ):
            captured["bounds_query"] = q
            return 10, 20

        MODULE.discover_numeric_bounds = fake_discover_numeric_bounds
        MODULE.MAX_INITIAL_INCIDENT_PARTITIONS = 4
        try:
            partitions = MODULE.build_incident_partitions(
                None,
                None,
                "https://example.invalid",
                4,
                "custom-query",
            )
        finally:
            MODULE.discover_numeric_bounds = original_discover_numeric_bounds
            MODULE.MAX_INITIAL_INCIDENT_PARTITIONS = original_max_initial_incident_partitions

        self.assertEqual(
            partitions,
            [
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 10,
                    "end": 12,
                    "count": None,
                    "query": (
                        "custom-query;"
                        "analyticsEventCreatedAtNano>9;analyticsEventCreatedAtNano<13"
                    ),
                },
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 13,
                    "end": 15,
                    "count": None,
                    "query": (
                        "custom-query;"
                        "analyticsEventCreatedAtNano>12;analyticsEventCreatedAtNano<16"
                    ),
                },
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 16,
                    "end": 18,
                    "count": None,
                    "query": (
                        "custom-query;"
                        "analyticsEventCreatedAtNano>15;analyticsEventCreatedAtNano<19"
                    ),
                },
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 19,
                    "end": 20,
                    "count": None,
                    "query": (
                        "custom-query;"
                        "analyticsEventCreatedAtNano>18;analyticsEventCreatedAtNano<21"
                    ),
                }
            ],
        )
        self.assertEqual(captured["bounds_query"], "custom-query")

    def test_wait_for_request_slot_uses_single_combined_wait(self):
        original_time_monotonic = MODULE.time.monotonic
        original_time_sleep = MODULE.time.sleep
        original_request_pacing_state = dict(MODULE.REQUEST_PACING_STATE)

        sleep_calls = []

        try:
            MODULE.REQUEST_PACING_STATE.clear()
            MODULE.REQUEST_PACING_STATE["/example"] = {
                "last_request_at": 100.0,
                "rate_limited_until": 105.0,
            }
            MODULE.time.monotonic = lambda: 100.0
            MODULE.time.sleep = sleep_calls.append

            MODULE.wait_for_request_slot("/example", 5.0)
        finally:
            MODULE.time.monotonic = original_time_monotonic
            MODULE.time.sleep = original_time_sleep
            MODULE.REQUEST_PACING_STATE.clear()
            MODULE.REQUEST_PACING_STATE.update(original_request_pacing_state)

        self.assertEqual(sleep_calls, [5.0])

    def test_fetch_partitioned_event_batches_refines_on_overflow(self):
        original_build_incident_partitions = MODULE.build_incident_partitions
        original_fetch_incident_partition_events = MODULE.fetch_incident_partition_events

        def fake_build_incident_partitions(
            session,
            headers,
            base_url,
            partition_max_records,
            incident_query,
        ):
            return [
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 1,
                    "end": 8,
                    "count": None,
                    "query": (
                        f"{MODULE.DETECTED_VULNERABILITY_QUERY};"
                        "analyticsEventCreatedAtNano>0;analyticsEventCreatedAtNano<9"
                    ),
                }
            ]

        def fake_fetch_incident_partition_events(
            session,
            headers,
            incident_url,
            page_size,
            partition,
        ):
            if partition["start"] == 1 and partition["end"] == 8:
                return [], False, True
            if partition["start"] == 1 and partition["end"] == 4:
                return [{"id": 1}], True, False
            if partition["start"] == 5 and partition["end"] == 8:
                return [{"id": 2}], True, False
            return [], True, False

        MODULE.build_incident_partitions = fake_build_incident_partitions
        MODULE.fetch_incident_partition_events = fake_fetch_incident_partition_events
        try:
            batches = list(
                MODULE.fetch_partitioned_event_batches(
                    None,
                    None,
                    "https://example.invalid",
                    500,
                    5000,
                    MODULE.DETECTED_VULNERABILITY_QUERY,
                )
            )
        finally:
            MODULE.build_incident_partitions = original_build_incident_partitions
            MODULE.fetch_incident_partition_events = original_fetch_incident_partition_events

        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0][0]["start"], 1)
        self.assertEqual(batches[0][0]["end"], 4)
        self.assertEqual(batches[1][0]["start"], 5)
        self.assertEqual(batches[1][0]["end"], 8)
        self.assertEqual(batches[0][1], [{"id": 1}])
        self.assertEqual(batches[1][1], [{"id": 2}])

    def test_fetch_incident_partition_events_refines_before_api_overflow(self):
        original_request_json = MODULE.request_json

        responses = [
            ({"serverResponseObject": [{"id": page}] * 500}, 200)
            for page in range(MODULE.INCIDENT_MAX_SAFE_PAGES)
        ]

        def fake_request_json(session, url, headers, params=None, timeout=None):
            if not responses:
                raise AssertionError("A função não deveria buscar a página além do limite seguro")
            return responses.pop(0)

        MODULE.request_json = fake_request_json
        try:
            events, complete, overflow = MODULE.fetch_incident_partition_events(
                None,
                None,
                "https://example.invalid/incidentEvent/filter",
                500,
                {
                    "field": MODULE.INCIDENT_PARTITION_FIELD,
                    "start": 1,
                    "end": 999,
                    "query": "dummy-query",
                },
            )
        finally:
            MODULE.request_json = original_request_json

        self.assertEqual(len(events), MODULE.INCIDENT_MAX_SAFE_PAGES * 500)
        self.assertFalse(complete)
        self.assertTrue(overflow)

    def test_refresh_inventory_cache_incremental_merges_new_records(self):
        existing_endpoints = [
            {
                "endpointId": 1,
                "endpointName": "host-a",
                "endpointCreatedAt": 100,
                "endpointOperatingSystem": {"operatingSystemName": "Linux"},
            }
        ]
        existing_attributes = [
            {
                "endpointAttributesEndpoint": {
                    "endpointId": 1,
                    "endpointName": "host-a",
                },
                "endpointAttributesAttribute": {
                    "attributeExternalId": "10.0.0.1",
                    "attributeAttributeSource": {
                        "attributeSourceName": "Internal IP Address"
                    },
                },
            }
        ]
        metadata = {
            "createdAt": "2026-03-20T00:00:00+00:00",
            "baseUrl": "https://example.invalid",
            "endpointsCount": 1,
            "endpointAttributesCount": 1,
            "inventoryRefreshMode": "partitioned",
            "partitionMaxRecords": 5000,
            "endpointPartitionField": MODULE.ENDPOINT_PARTITION_FIELD,
            "endpointAttributePartitionField": MODULE.ATTRIBUTE_PARTITION_FIELD,
            "endpointsComplete": True,
            "endpointAttributesComplete": True,
            "endpointPartitions": [
                {
                    "field": MODULE.ENDPOINT_PARTITION_FIELD,
                    "start": 100,
                    "end": 100,
                    "count": 1,
                    "query": "endpointCreatedAt>99;endpointCreatedAt<101",
                    "fetched": 1,
                    "complete": True,
                }
            ],
            "endpointAttributePartitions": [
                {
                    "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                    "start": 1,
                    "end": 1,
                    "count": None,
                    "query": "endpointId>0;endpointId<2",
                    "fetched": 1,
                    "complete": True,
                }
            ],
            "lastEndpointCreatedAt": 100,
            "lastFullRefreshAt": "2026-03-20T00:00:00+00:00",
        }

        original_discover_numeric_bounds = MODULE.discover_numeric_bounds
        original_build_numeric_partitions = MODULE.build_numeric_partitions
        original_fetch_partitioned_pages = MODULE.fetch_partitioned_pages
        original_time_sleep = MODULE.time.sleep

        def fake_discover_numeric_bounds(
            session,
            headers,
            url,
            field_name,
            include_fields=None,
            q="",
        ):
            return 100, 120

        def fake_build_numeric_partitions(
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
            return [
                {
                    "field": field_name,
                    "start": range_start,
                    "end": range_end,
                    "count": 1,
                    "query": "endpointCreatedAt>99;endpointCreatedAt<121",
                }
            ]

        def fake_fetch_partitioned_pages(
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
            if label == "endpoints incrementais":
                return (
                    [
                        {
                            "endpointId": 2,
                            "endpointName": "host-b",
                            "endpointCreatedAt": 120,
                            "endpointOperatingSystem": {
                                "operatingSystemName": "Windows"
                            },
                        }
                    ],
                    [
                        {
                            "field": MODULE.ENDPOINT_PARTITION_FIELD,
                            "start": 100,
                            "end": 120,
                            "count": 1,
                            "query": "endpointCreatedAt>99;endpointCreatedAt<121",
                            "fetched": 1,
                            "complete": True,
                        }
                    ],
                )

            if label == "atributos incrementais":
                return (
                    [
                        {
                            "endpointAttributesEndpoint": {
                                "endpointId": 2,
                                "endpointName": "host-b",
                            },
                            "endpointAttributesAttribute": {
                                "attributeExternalId": "10.0.0.2",
                                "attributeAttributeSource": {
                                    "attributeSourceName": "Internal IP Address"
                                },
                            },
                        }
                    ],
                    [
                        {
                            "field": MODULE.ATTRIBUTE_PARTITION_FIELD,
                            "start": 2,
                            "end": 2,
                            "count": None,
                            "query": "endpointId>1;endpointId<3",
                            "fetched": 1,
                            "complete": True,
                        }
                    ],
                )

            raise AssertionError(f"label inesperado: {label}")

        MODULE.discover_numeric_bounds = fake_discover_numeric_bounds
        MODULE.build_numeric_partitions = fake_build_numeric_partitions
        MODULE.fetch_partitioned_pages = fake_fetch_partitioned_pages
        MODULE.time.sleep = lambda seconds: None

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                MODULE.save_inventory_cache(
                    temp_dir,
                    existing_endpoints,
                    existing_attributes,
                    metadata,
                )

                merged_endpoints, merged_attributes, merged_metadata = (
                    MODULE.refresh_inventory_cache_incremental(
                        None,
                        None,
                        "https://example.invalid",
                        500,
                        500,
                        temp_dir,
                        5000,
                    )
                )
        finally:
            MODULE.discover_numeric_bounds = original_discover_numeric_bounds
            MODULE.build_numeric_partitions = original_build_numeric_partitions
            MODULE.fetch_partitioned_pages = original_fetch_partitioned_pages
            MODULE.time.sleep = original_time_sleep

        self.assertEqual(len(merged_endpoints), 2)
        self.assertEqual(len(merged_attributes), 2)
        self.assertEqual(merged_metadata["inventoryRefreshMode"], "incremental")
        self.assertEqual(merged_metadata["lastEndpointCreatedAt"], 120)
        self.assertEqual(merged_metadata["incrementalAddedEndpointsCount"], 1)
        self.assertEqual(
            merged_metadata["incrementalAddedEndpointAttributesCount"],
            1,
        )

    def test_refresh_inventory_cache_operation_uses_incremental_when_cache_exists(self):
        original_inventory_cache_exists = MODULE.inventory_cache_exists
        original_refresh_inventory_cache_incremental = (
            MODULE.refresh_inventory_cache_incremental
        )
        original_refresh_inventory_cache = MODULE.refresh_inventory_cache

        calls = []

        MODULE.inventory_cache_exists = lambda cache_dir: True
        MODULE.refresh_inventory_cache_incremental = lambda *args, **kwargs: calls.append(
            "incremental"
        ) or ([], [], {})
        MODULE.refresh_inventory_cache = lambda *args, **kwargs: calls.append("full") or (
            [],
            [],
            {},
        )

        try:
            MODULE.refresh_inventory_cache_operation(
                None,
                None,
                "https://example.invalid",
                500,
                500,
                cache_dir="/tmp/cache",
                partition_max_records=5000,
            )
        finally:
            MODULE.inventory_cache_exists = original_inventory_cache_exists
            MODULE.refresh_inventory_cache_incremental = (
                original_refresh_inventory_cache_incremental
            )
            MODULE.refresh_inventory_cache = original_refresh_inventory_cache

        self.assertEqual(calls, ["incremental"])

    def test_refresh_inventory_cache_operation_uses_full_when_cache_missing(self):
        original_inventory_cache_exists = MODULE.inventory_cache_exists
        original_refresh_inventory_cache_incremental = (
            MODULE.refresh_inventory_cache_incremental
        )
        original_refresh_inventory_cache = MODULE.refresh_inventory_cache

        calls = []

        MODULE.inventory_cache_exists = lambda cache_dir: False
        MODULE.refresh_inventory_cache_incremental = lambda *args, **kwargs: calls.append(
            "incremental"
        ) or ([], [], {})
        MODULE.refresh_inventory_cache = lambda *args, **kwargs: calls.append("full") or (
            [],
            [],
            {},
        )

        try:
            MODULE.refresh_inventory_cache_operation(
                None,
                None,
                "https://example.invalid",
                500,
                500,
                cache_dir="/tmp/cache",
                partition_max_records=5000,
            )
        finally:
            MODULE.inventory_cache_exists = original_inventory_cache_exists
            MODULE.refresh_inventory_cache_incremental = (
                original_refresh_inventory_cache_incremental
            )
            MODULE.refresh_inventory_cache = original_refresh_inventory_cache

        self.assertEqual(calls, ["full"])

    def test_load_cached_inventory_lookups_fails_when_cache_is_missing(self):
        original_inventory_cache_exists = MODULE.inventory_cache_exists

        MODULE.inventory_cache_exists = lambda cache_dir: False
        try:
            with self.assertRaises(SystemExit) as ctx:
                MODULE.load_cached_inventory_lookups("/tmp/cache")
        finally:
            MODULE.inventory_cache_exists = original_inventory_cache_exists

        self.assertIn("Cache local do inventário não existe", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()