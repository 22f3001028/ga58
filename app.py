from flask import Flask, request, jsonify
from urllib.parse import urlparse, unquote
from pathlib import Path
import os
import socket
import ipaddress
import requests

app = Flask(__name__)

# Render allows writing in /tmp
BASE = Path("/tmp/agent-redteam")
SANDBOX = BASE / "sandbox-81cdc437b0"
OUTSIDE = BASE / "outside-21651560"

# Create required directories
(SANDBOX / "notes").mkdir(parents=True, exist_ok=True)
(SANDBOX / "encoded").mkdir(parents=True, exist_ok=True)
OUTSIDE.mkdir(parents=True, exist_ok=True)

# Create the required test files
(OUTSIDE / "canary.txt").write_text(
    "AGENT_GUARDRAIL_CANARY_8870aa06bca8ce7a0e0277d767381a3da3195f54"
)

(SANDBOX / "notes" / "report.txt").write_text(
    "SAFE_REPORT_eeed794517e55df90894a0a8"
)

(SANDBOX / "notes" / "looks-like-..-but-safe.txt").write_text(
    "SAFE_WEIRD_340a252c859f1960f01ca429"
)

(SANDBOX / "encoded" / "%2e%2e-literal.txt").write_text(
    "SAFE_ENCODED_483c8ec99b397defb911c412"
)


def normalize_path(user_path):
    """
    Convert the requested path into a safe normalized path.
    Handles URL encoding and relative path traversal.
    """
    if not isinstance(user_path, str):
        return None

    try:
        # Decode repeatedly to catch encoded traversal
        decoded = user_path
        for _ in range(3):
            new_value = unquote(decoded)
            if new_value == decoded:
                break
            decoded = new_value

        # Map the required grader sandbox path to our writable /tmp location
        required_root = "/srv/agent-redteam/sandbox-81cdc437b0"

        if decoded == required_root:
            relative = ""
        elif decoded.startswith(required_root + "/"):
            relative = decoded[len(required_root) + 1:]
        else:
            return None

        # Resolve the path safely
        target = (SANDBOX / relative).resolve()
        sandbox_root = SANDBOX.resolve()

        # Must remain inside sandbox
        if target != sandbox_root and sandbox_root not in target.parents:
            return None

        return target

    except Exception:
        return None


def is_private_or_blocked_host(hostname):
    """
    Reject private, loopback, metadata and other unsafe IP addresses.
    """
    if not hostname:
        return True

    hostname = hostname.lower().rstrip(".")

    # Exact allowlist
    if hostname not in {"example.com", "www.iana.org"}:
        return True

    # Resolve hostname and reject unsafe IPs
    try:
        addresses = socket.getaddrinfo(hostname, None)

        for item in addresses:
            ip = item[4][0]
            addr = ipaddress.ip_address(ip)

            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
                or addr.is_unspecified
            ):
                return True

    except Exception:
        return True

    return False


def safe_fetch(url):
    """
    Fetch only exact allowed HTTPS hosts.
    Redirects are disabled so redirects cannot bypass the hostname policy.
    """
    try:
        parsed = urlparse(url)

        # HTTPS only
        if parsed.scheme != "https":
            return None, "Only HTTPS requests are allowed."

        # No username/password tricks
        if parsed.username or parsed.password:
            return None, "URLs containing userinfo are blocked."

        hostname = parsed.hostname

        if is_private_or_blocked_host(hostname):
            return None, "Host is not allowed."

        # Do not follow redirects
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        # If server attempts redirect, block it
        if response.is_redirect or response.is_permanent_redirect:
            return None, "Redirects are blocked."

        return response.text[:10000], "Request completed successfully."

    except Exception as e:
        return None, "Request failed safely."


@app.route("/", methods=["GET", "HEAD"])
def home():
    return jsonify({
        "status": "ok",
        "service": "agent-redteam-guardrail"
    })


@app.route("/guardrail", methods=["POST"])
def guardrail():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "action": "block",
            "reason": "Invalid JSON request.",
            "result": ""
        }), 400

    tool = data.get("tool")
    arguments = data.get("arguments", {})

    if not isinstance(arguments, dict):
        return jsonify({
            "action": "block",
            "reason": "Invalid arguments.",
            "result": ""
        }), 400

    # ---------------------------------------------------------
    # READ FILE
    # ---------------------------------------------------------
    if tool == "read_file":
        path = arguments.get("path")

        target = normalize_path(path)

        if target is None:
            return jsonify({
                "action": "block",
                "reason": "Path is outside the allowed sandbox.",
                "result": ""
            })

        try:
            if not target.exists():
                return jsonify({
                    "action": "allow",
                    "reason": "Path is inside the allowed sandbox but does not exist.",
                    "result": ""
                })

            if not target.is_file():
                return jsonify({
                    "action": "block",
                    "reason": "Requested path is not a regular file.",
                    "result": ""
                })

            content = target.read_text(
                encoding="utf-8",
                errors="replace"
            )

            return jsonify({
                "action": "allow",
                "reason": "File is inside the allowed sandbox.",
                "result": content
            })

        except Exception:
            return jsonify({
                "action": "block",
                "reason": "Unable to safely read the requested file.",
                "result": ""
            })

    # ---------------------------------------------------------
    # FETCH URL
    # ---------------------------------------------------------
    elif tool == "fetch_url":
        url = arguments.get("url")

        if not isinstance(url, str):
            return jsonify({
                "action": "block",
                "reason": "Invalid URL.",
                "result": ""
            })

        parsed = urlparse(url)

        if not parsed.hostname:
            return jsonify({
                "action": "block",
                "reason": "Invalid URL hostname.",
                "result": ""
            })

        # Check before making request
        if is_private_or_blocked_host(parsed.hostname):
            return jsonify({
                "action": "block",
                "reason": "URL host is not on the exact allowlist.",
                "result": ""
            })

        content, reason = safe_fetch(url)

        if content is None:
            return jsonify({
                "action": "block",
                "reason": reason,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": reason,
            "result": content
        })

    # ---------------------------------------------------------
    # UNKNOWN TOOL
    # ---------------------------------------------------------
    else:
        return jsonify({
            "action": "block",
            "reason": "Unknown tool.",
            "result": ""
        })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host="0.0.0.0",
        port=port
    )
