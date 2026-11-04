"""Create the opt-in large analytics fixture on a disposable loopback Elasticsearch.

This creates a new index and never deletes or replaces an existing index.
"""
import http.client
import ipaddress
import json
import sys
from urllib.parse import urlsplit

INDEX = "network-mapping-scan-observations-v1-2099.01"
COUNT = 610_512
DISTINCT = 210_001


def request(conn, method, path, body, content_type="application/json"):
    conn.request(method, path, body=body, headers={"Content-Type": content_type})
    response = conn.getresponse()
    data = response.read()
    if not 200 <= response.status < 300:
        raise RuntimeError(f"Elasticsearch returned HTTP {response.status}: {data[:500]!r}")
    return json.loads(data)


def main():
    url = urlsplit(sys.argv[1] if len(sys.argv) == 2 else "http://127.0.0.1:19200")
    if url.scheme != "http" or url.hostname != "127.0.0.1" or url.path not in ("", "/") or url.query or url.fragment or url.username or url.password:
        raise SystemExit("Use a disposable unauthenticated Elasticsearch on http://127.0.0.1:<port>")
    conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=120)
    metadata = request(conn, "GET", "/", None)
    if not metadata.get("version", {}).get("number", "").startswith("9.5."):
        raise SystemExit("Fixture requires Elasticsearch 9.5.x")
    request(conn, "PUT", f"/{INDEX}", json.dumps({
        "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "-1"},
        "mappings": {"properties": {"execution_id": {"type": "keyword"}, "observed_at": {"type": "long"}}},
    }))
    for start in range(0, COUNT, 5000):
        records = []
        for n in range(start, min(start + 5000, COUNT)):
            key = n % DISTINCT
            records.append(json.dumps({"index": {"_index": INDEX, "_id": str(n)}}, separators=(",", ":")))
            records.append(json.dumps({
                "execution_id": "analytics-real-test", "kind": "service", "service": " HTTPS ",
                "ip_address": str(ipaddress.IPv4Address(0x0A000000 + key)), "port": 443,
                "endpoint_id": f"endpoint-{key}", "observed_at": 1788266400000 + (n // DISTINCT) * 1000,
            }, separators=(",", ":")))
        result = request(conn, "POST", "/_bulk", "\n".join(records) + "\n", "application/x-ndjson")
        if result.get("errors"):
            raise RuntimeError("Bulk import failed; inspect the disposable Elasticsearch logs")
        print(f"Imported {min(start + 5000, COUNT)}/{COUNT}", flush=True)
    request(conn, "POST", f"/{INDEX}/_refresh", "{}")
    result = request(conn, "GET", f"/{INDEX}/_count", None)
    if result.get("count") != COUNT:
        raise RuntimeError(f"Fixture count mismatch: {result.get('count')}")
    print(f"Fixture ready: {INDEX} ({COUNT} observations)")


if __name__ == "__main__":
    main()
