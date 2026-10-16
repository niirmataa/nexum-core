#!/usr/bin/python3
"""OPS/MANUAL: STUB granicy wallet-rpc dla etapu all-in-one (sekcja C).

To NIE jest wallet-rpc. Odpowiada na /json_rpc kontraktem pochodzacym
z mocka testowego (tests/support/mod.rs, wallet_rpc_handler), zeby
signery mogly wystartowac bez granicy Monero.

Roadmapa D (monero-a/monero-b + wallet-rpc loopback-only) zastepuje
tego stuba prawdziwym wallet-rpc. Wszelkie operacje finansowe na stubie
sa celowo niewykonalne (brak realnych metod portfela).

Usage: wallet-rpc-stub.py [port]   (domyslnie 38088, loopback only)
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

RESPONSES = {
    "open_wallet": {},
    "close_wallet": {},
    "is_multisig": {"multisig": True, "ready": True, "threshold": 2, "total": 3},
    "describe_transfer": {
        "desc": [{
            "recipients": [{"address": "release_addr", "amount": 100}],
            "fee": 10,
            "unlock_time": 0,
            "dummy_outputs": 0,
        }]
    },
    "sign_multisig": {"tx_data_hex": "aa11", "tx_hash_list": ["abcd"]},
    "submit_multisig": {"tx_hash_list": ["submithash"]},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/json_rpc":
            self.send_error(404, "stub serves /json_rpc only")
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            req = {}
        method = req.get("method", "")
        req_id = req.get("id", "0")
        if method in RESPONSES:
            body = {"jsonrpc": "2.0", "id": req_id, "result": RESPONSES[method]}
        else:
            body = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -1, "message": f"unsupported stub method: {method}"},
            }
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"wallet-rpc-stub: {fmt % args}", flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 38088
    print(f"wallet-rpc-stub: STUB etapu C listening on 127.0.0.1:{port}", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
