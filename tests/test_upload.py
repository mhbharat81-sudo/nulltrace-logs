"""
Test upload endpoint for local security log files.
"""
import io
try:
    import pytest
except ImportError:
    pytest = None
from fastapi.testclient import TestClient
from backend.api.main import app

def test_upload_jsonl_log_file():
    client = TestClient(app)
    
    # Create sample JSONL log content
    sample_content = (
        '{"@timestamp": "2026-10-31T12:00:00Z", "host": {"name": "WS-TEST-001"}, "user": {"name": "CORP\\\\testuser"}, "threat": {"technique": {"id": "T1059.001", "name": "PowerShell Script"}, "tactic": {"name": "Execution"}}, "rule": {"id": "rule-01", "name": "Suspicious PowerShell"}}\n'
        '{"@timestamp": "2026-10-31T12:01:00Z", "host": {"name": "WS-TEST-001"}, "user": {"name": "CORP\\\\testuser"}, "dns": {"question": {"name": "suspicious-example-c2.invalid"}}, "threat": {"technique": {"id": "T1071.001", "name": "C2 Beacon"}, "tactic": {"name": "Command and Control"}}, "rule": {"id": "rule-02", "name": "C2 Domain Beacon"}}\n'
    )
    
    file_bytes = io.BytesIO(sample_content.encode("utf-8"))
    files = {"file": ("test_edr.jsonl", file_bytes, "application/json")}
    
    response = client.post("/api/upload-log", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_records"] == 2
    assert "upload-" in data["dataset_id"]
    assert data["detections_count"] >= 1
    assert data["graph_nodes"] >= 2


def test_upload_fortigate_kv_log_file():
    client = TestClient(app)
    
    sample_kv = (
        'date=2026-10-31 time=14:00:00 devname="FW-GATEWAY-01" srcip=192.168.1.100 dstip=10.10.99.1 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" action="blocked"\n'
        'date=2026-10-31 time=14:02:00 devname="FW-GATEWAY-01" srcip=192.168.1.100 dstip=10.10.0.1 attack="ZeroLogon.Netlogon.Privilege.Escalation" action="detected"\n'
    )
    
    file_bytes = io.BytesIO(sample_kv.encode("utf-8"))
    files = {"file": ("firewall_sample.log", file_bytes, "text/plain")}
    
    response = client.post("/api/upload-log", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_records"] == 2
    assert data["format"] == "kv_log"
    assert data["detections_count"] >= 1


def test_resumable_chunked_upload_and_job_pipeline():
    import time
    client = TestClient(app)
    upload_id = f"test_resumable_{int(time.time())}"

    # Check initial status
    resp = client.get(f"/api/upload-chunk/status?upload_id={upload_id}")
    assert resp.status_code == 200
    assert resp.json()["uploaded_chunks"] == []

    # Prepare 2 chunks of log lines
    chunk0 = b'{"@timestamp": "2026-10-31T12:00:00Z", "host": {"name": "WS-CHUNK-01"}, "threat": {"technique": {"id": "T1059.001", "name": "PowerShell"}}}\n'
    chunk1 = b'{"@timestamp": "2026-10-31T12:01:00Z", "host": {"name": "WS-CHUNK-01"}, "dns": {"question": {"name": "c2.beacon.invalid"}}, "threat": {"technique": {"id": "T1071.001", "name": "C2"}}}\n'

    # Upload chunk 0
    resp0 = client.post(
        "/api/upload-chunk",
        data={"upload_id": upload_id, "chunk_index": 0, "total_chunks": 2, "filename": "large_test.jsonl"},
        files={"chunk": ("chunk0.part", io.BytesIO(chunk0), "application/octet-stream")}
    )
    assert resp0.status_code == 200
    assert resp0.json()["chunk_index"] == 0

    # Verify status reflects chunk 0
    resp = client.get(f"/api/upload-chunk/status?upload_id={upload_id}")
    assert resp.json()["uploaded_chunks"] == [0]

    # Upload chunk 1
    resp1 = client.post(
        "/api/upload-chunk",
        data={"upload_id": upload_id, "chunk_index": 1, "total_chunks": 2, "filename": "large_test.jsonl"},
        files={"chunk": ("chunk1.part", io.BytesIO(chunk1), "application/octet-stream")}
    )
    assert resp1.status_code == 200
    assert resp1.json()["chunk_index"] == 1

    # Verify status reflects [0, 1]
    resp = client.get(f"/api/upload-chunk/status?upload_id={upload_id}")
    assert resp.json()["uploaded_chunks"] == [0, 1]

    # Complete upload
    comp_resp = client.post("/api/upload-complete", json={
        "upload_id": upload_id,
        "filename": "large_test.jsonl",
        "total_chunks": 2,
        "max_records": 1000
    })
    assert comp_resp.status_code == 200
    assert comp_resp.json()["status"] == "accepted"

    # Poll for completion
    data = {}
    for _ in range(50):
        job_resp = client.get(f"/api/upload-job/{upload_id}")
        assert job_resp.status_code == 200
        data = job_resp.json()
        if data["status"] == "completed":
            break
        elif data["status"] == "failed":
            pytest.fail(f"Job failed: {data.get('error')}")
        time.sleep(0.1)

    assert data["status"] == "completed"
    assert data["result"]["total_records"] == 2
    assert data["result"]["status"] == "success"


def test_resumable_compressed_chunk_upload():
    import gzip
    import time
    client = TestClient(app)
    upload_id = f"test_compressed_{int(time.time())}"

    # Prepare raw log line and compress with gzip
    raw_log = b'{"@timestamp": "2026-10-31T12:05:00Z", "host": {"name": "WS-TURBO-01"}, "threat": {"technique": {"id": "T1059.001", "name": "Macro"}}}\n' * 50
    compressed_bytes = gzip.compress(raw_log)
    assert len(compressed_bytes) < len(raw_log)

    # Upload single compressed chunk
    resp = client.post(
        "/api/upload-chunk",
        data={
            "upload_id": upload_id,
            "chunk_index": 0,
            "total_chunks": 1,
            "filename": "turbo_compressed.jsonl",
            "is_compressed": "true"
        },
        files={"chunk": ("chunk0.part", io.BytesIO(compressed_bytes), "application/gzip")}
    )
    assert resp.status_code == 200
    assert resp.json()["bytes"] == len(raw_log)  # Verifies server decompressed it!

    # Complete upload
    comp_resp = client.post("/api/upload-complete", json={
        "upload_id": upload_id,
        "filename": "turbo_compressed.jsonl",
        "total_chunks": 1,
        "max_records": 1000
    })
    assert comp_resp.status_code == 200

    # Poll for completion
    data = {}
    for _ in range(50):
        job_resp = client.get(f"/api/upload-job/{upload_id}")
        data = job_resp.json()
        if data["status"] == "completed":
            break
        elif data["status"] == "failed":
            pytest.fail(f"Job failed: {data.get('error')}")
        time.sleep(0.1)

    assert data["status"] == "completed"
    assert data["result"]["total_records"] == 50


def test_local_log_files_endpoint():
    client = TestClient(app)
    resp = client.get("/api/local-log-files")
    assert resp.status_code == 200
    files = resp.json()
    assert isinstance(files, list)
    names = [f["name"] for f in files]
    assert "50g_log.json" in names or "edr_10000_logs.json" in names


def test_ingest_local_endpoint_and_reset():
    import time
    client = TestClient(app)

    # Ingest local file with sample 10 records
    resp = client.post("/api/ingest-local", json={
        "file_path": "edr_10000_logs.json",
        "dataset_name": "Test Local Ingest",
        "max_records": 10
    })
    assert resp.status_code == 200
    upload_id = resp.json()["upload_id"]

    for _ in range(50):
        job_resp = client.get(f"/api/upload-job/{upload_id}")
        data = job_resp.json()
        if data["status"] == "completed":
            break
        time.sleep(0.1)

    assert data["status"] == "completed"
    assert data["result"]["total_records"] == 10

    # Test reset endpoint
    reset_resp = client.post("/api/datasets/reset", json={"mode": "purge_uploads"})
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "ok"


def test_in_flight_threat_interception():
    """Verify in-flight threat interception captures threats with automated countermeasures."""
    import time
    client = TestClient(app)

    sample_threat_stream = (
        '{"@timestamp": "2026-10-31T12:00:00Z", "host": {"name": "SRV-DMZ-01"}, "source": {"ip": "45.74.28.219"}, "destination": {"ip": "10.10.20.50", "port": 8080}, "attack": "Apache.Log4j.Error.Log.Remote.Code.Execution", "msg": "JNDI exploit attempt detected"}\n'
        '{"@timestamp": "2026-10-31T12:00:05Z", "host": {"name": "SRV-DC-01"}, "source": {"ip": "10.10.20.15"}, "destination": {"ip": "10.10.99.1", "port": 135}, "attack": "ZeroLogon.Netlogon.Privilege.Escalation", "msg": "ZeroLogon Netlogon domain elevation attempt"}\n'
        '{"@timestamp": "2026-10-31T12:00:10Z", "host": {"name": "WS-LAN-04"}, "source": {"ip": "10.10.10.40"}, "destination": {"ip": "185.190.140.22", "port": 443}, "threat": {"technique": {"id": "T1071.001", "name": "Cobalt Strike C2 Beacon"}}, "severity": 9}\n'
    )

    upload_id = f"test_inflight_{int(time.time())}"
    resp = client.post(
        "/api/upload-log",
        data={"upload_id": upload_id},
        files={"file": ("live_threats.jsonl", io.BytesIO(sample_threat_stream.encode("utf-8")), "application/json")}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"

    # Poll upload job
    data = {}
    for _ in range(50):
        job_resp = client.get(f"/api/upload-job/{upload_id}")
        assert job_resp.status_code == 200
        data = job_resp.json()
        if data["status"] == "completed":
            break
        time.sleep(0.1)

    assert data["status"] == "completed"
    assert data["records_processed"] == 3
    assert data["threats_intercepted_count"] >= 3
    assert data["critical_blocks_count"] >= 2
    assert len(data["in_flight_intercepts"]) >= 3

    # Check threat structure & mitigations
    first_threat = data["in_flight_intercepts"][0]
    assert "technique_id" in first_threat
    assert "technique_name" in first_threat
    assert "action" in first_threat
    assert "mitigation" in first_threat
    assert "Virtual Patch" in first_threat["mitigation"] or "Shielded" in first_threat["mitigation"]

    # Clean up test dataset
    client.post("/api/datasets/reset", json={"mode": "purge_uploads"})



