from flask import Flask, request, jsonify
import os
import ipaddress
import socket
from urllib.parse import urlparse, unquote
import requests

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-81cdc437b0"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


# ============================================================
# HELPER: SAFE PATH CHECK
# ============================================================

def safe_path(path):
    """
    Returns (True, normalized_path) if the path is inside
    the allowed sandbox directory.
    Otherwise returns (False, None).
    """

    if not isinstance(path, str):
        return False, None

    # Decode URL-style encoding such as %2e%2e
    decoded = unquote(path)

    # Convert to an absolute normalized path.
    # realpath also resolves .. and symbolic links.
    full_path = os.path.realpath(decoded)

    # Normalize the sandbox root too.
    root = os.path.realpath(SANDBOX_ROOT)

    try:
        common = os.path.commonpath([full_path, root])
    except ValueError:
        return False, None

    # The path must be inside the sandbox.
    # This also allows subdirectories.
    if common != root:
        return False, None

    return True, full_path


# ============================================================
# HELPER: CHECK WHETHER AN IP IS PRIVATE/DANGEROUS
# ============================================================

def is_dangerous_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)

        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )

    except ValueError:
        return True


# ============================================================
# HELPER: SAFE URL CHECK
# ============================================================

def safe_url(url):
    """
    Checks whether a URL is allowed.

    Only:
        example.com
        www.iana.org

    are allowed.
    """

    if not isinstance(url, str):
        return False, "URL must be a string"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"

    # Only HTTP and HTTPS
    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed"

    # Must have a hostname
    if not parsed.hostname:
        return False, "URL has no hostname"

    # Reject username/password in URLs.
    # Example:
    # https://example.com@evil.com
    if parsed.username is not None or parsed.password is not None:
        return False, "URLs containing userinfo are blocked"

    hostname = parsed.hostname.lower().rstrip(".")

    # EXACT hostname comparison.
    # This prevents:
    # example.com.evil.com
    # example.com.attacker.com
    # evil-example.com
    if hostname not in ALLOWED_HOSTS:
        return False, "Host is not on the allowlist"

    # Resolve the hostname.
    # This helps detect DNS pointing to private addresses.
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            proto=socket.IPPROTO_TCP
        )

        for item in addresses:
            ip = item[4][0]

            if is_dangerous_ip(ip):
                return False, "Host resolves to a restricted IP address"

    except Exception:
        return False, "Could not safely resolve host"

    return True, hostname


# ============================================================
# TOOL: READ FILE
# ============================================================

def read_file(path):
    allowed, normalized_path = safe_path(path)

    if not allowed:
        return {
            "action": "block",
            "reason": "Path is outside the allowed sandbox.",
            "result": "File access blocked."
        }

    try:
        with open(normalized_path, "r", encoding="utf-8") as f:
            content = f.read()

        return {
            "action": "allow",
            "reason": "File is inside the allowed sandbox.",
            "result": content
        }

    except Exception as e:
        return {
            "action": "allow",
            "reason": "File is inside the allowed sandbox but could not be read.",
            "result": str(e)
        }


# ============================================================
# TOOL: FETCH URL
# ============================================================

def fetch_url(url):

    allowed, info = safe_url(url)

    if not allowed:
        return {
            "action": "block",
            "reason": info,
            "result": "URL fetch blocked."
        }

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        # Do not blindly follow redirects.
        # Check the redirect destination separately.
        if response.is_redirect or response.is_permanent_redirect:

            location = response.headers.get("Location", "")

            redirect_allowed, redirect_info = safe_url(location)

            if not redirect_allowed:
                return {
                    "action": "block",
                    "reason": "Redirect destination is not allowed.",
                    "result": "URL fetch blocked."
                }

            # Only redirect to an allowed host.
            response = requests.get(
                location,
                timeout=5,
                allow_redirects=False
            )

        return {
            "action": "allow",
            "reason": "Host is on the exact allowlist.",
            "result": response.text
        }

    except Exception as e:

        return {
            "action": "allow",
            "reason": "Allowed host but request failed.",
            "result": str(e)
        }


# ============================================================
# MAIN ENDPOINT
# ============================================================

@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "action": "block",
            "reason": "Invalid JSON request.",
            "result": "Request blocked."
        })

    tool = data.get("tool")
    arguments = data.get("arguments", {})

    if not isinstance(arguments, dict):
        return jsonify({
            "action": "block",
            "reason": "Arguments must be an object.",
            "result": "Request blocked."
        })

    # --------------------------------------------------------
    # read_file
    # --------------------------------------------------------

    if tool == "read_file":

        path = arguments.get("path")

        if path is None:
            return jsonify({
                "action": "block",
                "reason": "Missing file path.",
                "result": "Request blocked."
            })

        return jsonify(read_file(path))


    # --------------------------------------------------------
    # fetch_url
    # --------------------------------------------------------

    if tool == "fetch_url":

        url = arguments.get("url")

        if url is None:
            return jsonify({
                "action": "block",
                "reason": "Missing URL.",
                "result": "Request blocked."
            })

        return jsonify(fetch_url(url))


    # --------------------------------------------------------
    # Unknown tool
    # --------------------------------------------------------

    return jsonify({
        "action": "block",
        "reason": "Unknown tool.",
        "result": "Request blocked."
    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port
    )
