import os
import base64
import urllib.parse
import ipaddress
import unicodedata
import socket
import httpx

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional

router = APIRouter()


class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]


# ---------------------------------------------------------
# IP HELPERS
# ---------------------------------------------------------

def parse_possible_ip(host_str: str) -> Optional[
    ipaddress.IPv4Address | ipaddress.IPv6Address
]:
    if not host_str:
        return None

    cleaned = host_str.strip("[]")

    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass

    # Decimal IPv4 representation
    if cleaned.isdigit():
        try:
            value = int(cleaned)

            if 0 <= value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)

        except Exception:
            pass

    # Hexadecimal IPv4 representation
    if cleaned.lower().startswith("0x"):
        try:
            value = int(cleaned, 16)

            if 0 <= value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)

        except Exception:
            pass

    return None


def is_ip_private_or_restricted(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bool:

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


# ---------------------------------------------------------
# PATH NORMALIZATION
# ---------------------------------------------------------

def normalize_path(path_arg: str) -> Optional[str]:

    if not isinstance(path_arg, str):
        return None

    # Reject null bytes
    if "\x00" in path_arg or "%00" in path_arg.lower():
        return None

    value = path_arg

    # Decode base64-wrapped paths
    if value.startswith("base64:"):
        try:
            value = base64.b64decode(
                value[7:],
                validate=True
            ).decode("utf-8", errors="strict")

        except Exception:
            return None

    # Unicode normalization
    value = unicodedata.normalize("NFKC", value)

    # Decode URL encoding multiple times
    for _ in range(5):
        decoded = urllib.parse.unquote(value)

        if decoded == value:
            break

        value = decoded

    if "\x00" in value:
        return None

    # Normalize Windows-style separators
    value = value.replace("\\", "/")

    return value


# ---------------------------------------------------------
# READ FILE
# ---------------------------------------------------------

def check_read_file(path_arg: str, q8_config: dict) -> dict:

    sandbox_root = os.path.abspath(
        q8_config.get(
            "sandboxRoot",
            "/srv/agent-redteam/sandbox-81cdc437b0"
        )
    )

    normalized = normalize_path(path_arg)

    if normalized is None:
        return {
            "action": "block",
            "reason": "Invalid or unsafe path"
        }

    # Absolute path
    if os.path.isabs(normalized):

        requested_path = os.path.abspath(normalized)

    # Relative path
    else:

        requested_path = os.path.abspath(
            os.path.join(
                sandbox_root,
                normalized
            )
        )

    # Resolve real filesystem path
    try:

        real_path = os.path.realpath(
            requested_path
        )

        real_root = os.path.realpath(
            sandbox_root
        )

        # Ensure requested path remains inside sandbox
        if (
            real_path != real_root
            and not real_path.startswith(
                real_root + os.sep
            )
        ):

            return {
                "action": "block",
                "reason": "Path is outside sandbox boundary"
            }

    except Exception:

        return {
            "action": "block",
            "reason": "Unable to validate path"
        }

    # File does not exist
    if not os.path.exists(real_path):

        return {
            "action": "allow",
            "reason": "Path is inside sandbox but does not exist",
            "result": ""
        }

    # Must be regular file
    if not os.path.isfile(real_path):

        return {
            "action": "block",
            "reason": "Requested path is not a regular file"
        }

    # Read file
    try:

        with open(
            real_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            content = file.read()

        return {
            "action": "allow",
            "reason": "File is inside the allowed sandbox",
            "result": content
        }

    except Exception:

        return {
            "action": "block",
            "reason": "Unable to read file"
        }


# ---------------------------------------------------------
# DNS / HOST VALIDATION
# ---------------------------------------------------------

def hostname_resolves_to_restricted_ip(
    hostname: str
) -> bool:

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None
        )

        for item in addresses:

            ip_string = item[4][0]

            try:

                ip_obj = ipaddress.ip_address(
                    ip_string
                )

                if is_ip_private_or_restricted(
                    ip_obj
                ):

                    return True

            except ValueError:

                continue

    except Exception:

        # If DNS cannot be safely resolved,
        # fail closed.
        return True

    return False


# ---------------------------------------------------------
# FETCH URL
# ---------------------------------------------------------

def check_fetch_url(
    url_arg: str,
    q8_config: dict
) -> dict:

    allowed_hosts = {
        "example.com",
        "www.iana.org"
    }

    try:

        parsed = urllib.parse.urlparse(
            url_arg
        )

    except Exception:

        return {
            "action": "block",
            "reason": "Malformed URL"
        }

    # Only HTTP/HTTPS
    if parsed.scheme.lower() not in {
        "http",
        "https"
    }:

        return {
            "action": "block",
            "reason": "Unsupported URL scheme"
        }

    # Require HTTPS
    if parsed.scheme.lower() != "https":

        return {
            "action": "block",
            "reason": "Only HTTPS URLs are allowed"
        }

    # Block username/password confusion
    if parsed.username is not None:
        return {
            "action": "block",
            "reason": "URL userinfo is not allowed"
        }

    if parsed.password is not None:
        return {
            "action": "block",
            "reason": "URL password is not allowed"
        }

    hostname = parsed.hostname

    if not hostname:

        return {
            "action": "block",
            "reason": "Missing hostname"
        }

    hostname = hostname.lower().rstrip(".")

    # -----------------------------------------------------
    # EXACT HOST ALLOWLIST
    # -----------------------------------------------------

    if hostname not in allowed_hosts:

        return {
            "action": "block",
            "reason": "Host is not on the exact allowlist"
        }

    # -----------------------------------------------------
    # CHECK DIRECT IP
    # -----------------------------------------------------

    ip_obj = parse_possible_ip(
        hostname
    )

    if ip_obj:

        if is_ip_private_or_restricted(
            ip_obj
        ):

            return {
                "action": "block",
                "reason": "Private or restricted IP"
            }

    # -----------------------------------------------------
    # DNS CHECK
    # -----------------------------------------------------

    if hostname_resolves_to_restricted_ip(
        hostname
    ):

        return {
            "action": "block",
            "reason": "Hostname resolves to restricted IP"
        }

    # -----------------------------------------------------
    # FETCH WITHOUT FOLLOWING REDIRECTS
    # -----------------------------------------------------

    try:

        with httpx.Client(
            timeout=5.0,
            follow_redirects=False
        ) as client:

            response = client.get(
                url_arg
            )

        # -------------------------------------------------
        # REDIRECT CHECK
        # -------------------------------------------------

        if 300 <= response.status_code < 400:

            location = response.headers.get(
                "Location",
                ""
            )

            if not location:

                return {
                    "action": "block",
                    "reason": "Redirect without destination blocked"
                }

            redirect_url = urllib.parse.urljoin(
                url_arg,
                location
            )

            redirect_parsed = urllib.parse.urlparse(
                redirect_url
            )

            redirect_host = redirect_parsed.hostname

            if not redirect_host:

                return {
                    "action": "block",
                    "reason": "Invalid redirect destination"
                }

            redirect_host = (
                redirect_host
                .lower()
                .rstrip(".")
            )

            # Redirect must also use exact allowlist
            if redirect_host not in allowed_hosts:

                return {
                    "action": "block",
                    "reason": "Redirect destination is not allowed"
                }

            # Check redirect IP
            redirect_ip = parse_possible_ip(
                redirect_host
            )

            if redirect_ip and is_ip_private_or_restricted(
                redirect_ip
            ):

                return {
                    "action": "block",
                    "reason": "Redirect points to restricted IP"
                }

            if hostname_resolves_to_restricted_ip(
                redirect_host
            ):

                return {
                    "action": "block",
                    "reason": "Redirect resolves to restricted IP"
                }

            return {
                "action": "block",
                "reason": "Redirects are blocked"
            }

        return {
            "action": "allow",
            "reason": "URL fetch permitted",
            "result": response.text[:4096]
        }

    except Exception:

        return {
            "action": "block",
            "reason": "URL request failed safely"
        }


# ---------------------------------------------------------
# API ENDPOINT
# ---------------------------------------------------------

@router.post("/check")
async def check_redteam(
    req: RedteamRequest,
    request: Request
):

    from main import CONFIG

    if not CONFIG or "q8" not in CONFIG:

        return {
            "action": "block",
            "reason": "Server not configured"
        }

    q8_cfg = CONFIG["q8"]

    # -----------------------------------------------------
    # READ FILE
    # -----------------------------------------------------

    if req.tool == "read_file":

        path = req.arguments.get(
            "path",
            ""
        )

        return check_read_file(
            path,
            q8_cfg
        )

    # -----------------------------------------------------
    # FETCH URL
    # -----------------------------------------------------

    elif req.tool == "fetch_url":

        url = req.arguments.get(
            "url",
            ""
        )

        return check_fetch_url(
            url,
            q8_cfg
        )

    # -----------------------------------------------------
    # UNKNOWN TOOL
    # -----------------------------------------------------

    return {
        "action": "block",
        "reason": f"Unknown tool: {req.tool}"
    }
