#!/usr/bin/env python3
"""
utils.py
--------
Stores general global constants and helper functions.
All HTTP requests/responses are treated as byte arrays.
Only the header is parsed as text; the body remains raw.
"""

import http.client

# Global constants (used by both client and server)
UDP_PORT = 9953                # DNS tunnel server listening port
FIXED_DOMAIN = "example.com"   # Fixed domain suffix

def split_txt(text, max_length=200):
    """
    Split the text into multiple strings by max_length,
    leaving some space for metadata (TXT single string limit is 255).
    Input and output are str.
    """
    return [text[i:i+max_length] for i in range(0, len(text), max_length)]

def split_encoded(encoded, max_label=50):
    """
    Split the encoded string into multiple segments that do not exceed max_label in length.
    Input and output are str.
    """
    return [encoded[i:i+max_label] for i in range(0, len(encoded), max_label)]

def extract_encoded_request(qname, domain=FIXED_DOMAIN):
    """
    For non-segmented requests, extract the encoded string from the query name.
    Format: <encoded segments>.<fixed_domain>
    Returns a str.
    """
    if qname.endswith('.'):
        qname = qname[:-1]
    labels = qname.split('.')
    domain_labels = domain.split('.')
    if len(labels) < len(domain_labels):
        return None
    if labels[-len(domain_labels):] != domain_labels:
        return "".join(labels)
    encoded_labels = labels[:-len(domain_labels)]
    return "".join(encoded_labels)

def format_txt_response(record_id, total, seg, chunk):
    """
    Construct the TXT response content in the format:
      R:<record_id>;T:<total_segments>;S:<current_segment>;D:<data>
    The data (chunk) is a str (e.g. a Base32-encoded segment).
    """
    return f"R:{record_id};T:{total};S:{seg};D:{chunk}"

def forward_http_request(http_request_bytes):
    """
    Forward the HTTP request to the target server.
    The input is a byte array representing the entire HTTP request.
    The header part is parsed (assumed to be ASCII) to extract method, path, etc.,
    but the body remains unchanged.
    Returns the complete HTTP response as a byte array.
    """
    # Partition the request into header and body parts
    header_part, sep, body = http_request_bytes.partition(b"\r\n\r\n")
    if not header_part:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    try:
        header_text = header_part.decode('ascii')
    except Exception:
        header_text = header_part.decode('utf-8', errors='replace')
    header_lines = header_text.split("\r\n")
    request_line = header_lines[0]
    parts = request_line.split()
    if len(parts) < 3:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    method, path, version = parts
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            headers[header_name.strip()] = header_value.strip()
    if "Host" not in headers:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\nMissing Host header"
    host = headers["Host"]
    if ':' in host:
        hostname = host.split(':')[0]
        try:
            port = int(host.split(':')[1])
        except:
            port = 80
    else:
        hostname = host
        port = 80

    try:
        conn = http.client.HTTPConnection(hostname, port, timeout=10)
        # For POST, pass the body bytes unchanged.
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read()
        status_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
        response_headers = ""
        for header, value in response.getheaders():
            response_headers += f"{header}: {value}\r\n"
        full_response = (status_line + response_headers + "\r\n").encode('ascii') + response_body
        return full_response
    except Exception as e:
        error_response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\nError: {e}"
        return error_response.encode('ascii')
