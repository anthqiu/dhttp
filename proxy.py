#!/usr/bin/env python3
"""
proxy.py
--------
HTTP proxy that forwards all incoming HTTP requests (of any type)
through the DNS tunnel server. The entire HTTP request/response is handled as a byte array;
only the header is parsed (as ASCII) for processing.
Uses Flask to accept external HTTP requests.

Usage:
    python proxy.py <dns_tunnel_server_ip>

For example:
    python proxy.py 192.168.1.100
"""

from flask import Flask, request, Response
from client import send_request, send_segmented_request

app = Flask(__name__)

# DNS tunnel server IP will be set via command-line argument.
DNS_TUNNEL_SERVER_IP = None  # Will be set in __main__

def parse_http_response(response_bytes):
    """
    Parse the HTTP response bytes into (status, headers, body).
    Only the header is decoded (assuming ASCII) to extract the status line and headers.
    The body remains as raw bytes.
    This function removes any Transfer-Encoding header.
    """
    header_part, sep, body = response_bytes.partition(b"\r\n\r\n")
    try:
        header_text = header_part.decode('ascii', errors='replace')
    except Exception:
        header_text = header_part.decode('utf-8', errors='replace')
    lines = header_text.split("\r\n")
    if not lines:
        return 502, {}, body
    # Parse the status line (e.g., "HTTP/1.1 200 OK")
    status_line = lines[0]
    parts = status_line.split()
    try:
        status = int(parts[1])
    except Exception:
        status = 502
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    # Remove Transfer-Encoding header if present
    headers.pop("Transfer-Encoding", None)
    # Optionally, set Content-Length header based on the length of the body
    headers["Content-Length"] = str(len(body))
    return status, headers, body

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    """
    Flask route to catch all HTTP requests.
    Reconstructs the raw HTTP request (as bytes) from Flask's request object,
    then forwards it via the DNS tunnel and returns the response.
    """
    # Reconstruct request line (method, path, and HTTP version)
    method = request.method
    qs = request.query_string.decode('ascii') if request.query_string else ""
    full_path = f"/{path}"
    if qs:
        full_path += "?" + qs
    request_line = f"{method} {full_path} HTTP/1.1\r\n".encode('ascii')

    # Rebuild headers (assuming header values are ASCII)
    headers_bytes = b""
    for key, value in request.headers.items():
        headers_bytes += f"{key}: {value}\r\n".encode('ascii')

    # Get raw body bytes
    body_bytes = request.get_data()

    # Construct the complete raw HTTP request as bytes
    raw_http_request = request_line + headers_bytes + b"\r\n" + body_bytes

    # Forward the raw HTTP request via the DNS tunnel.
    # Use segmented sending if the request is larger than a threshold (e.g., 1000 bytes)
    if len(raw_http_request) > 50:
        response_bytes = send_segmented_request(raw_http_request, DNS_TUNNEL_SERVER_IP)
    else:
        response_bytes = send_request(raw_http_request, DNS_TUNNEL_SERVER_IP)

    if response_bytes is None:
        return Response("DNS Tunnel error", status=502)

    # Parse the HTTP response (only header parsing is performed)
    status, resp_headers, resp_body = parse_http_response(response_bytes)

    # Return the response using Flask's Response object.
    return Response(resp_body, status=status, headers=resp_headers)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python proxy.py <dns_tunnel_server_ip>")
        DNS_TUNNEL_SERVER_IP = '127.0.0.1'
    else:
        DNS_TUNNEL_SERVER_IP = sys.argv[1]
    print(f"Using DNS Tunnel Server IP: {DNS_TUNNEL_SERVER_IP}")
    # Run the proxy on all interfaces on port 8080.
    app.run(host="0.0.0.0", port=8080)
