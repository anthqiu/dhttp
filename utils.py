"""
utils.py
--------
Stores general global constants and helper functions
"""

import http.client

# Global constants (used by both client and server)
UDP_PORT = 9953                # DNS tunnel server listening port
FIXED_DOMAIN = "example.com"   # Fixed domain suffix

def split_txt(text, max_length=200):
    """
    Split the text into multiple strings by max_length,
    leaving some space for metadata (TXT single string limit is 255).
    """
    return [text[i:i+max_length] for i in range(0, len(text), max_length)]

def split_encoded(encoded, max_label=50):
    """
    Split the encoded string into multiple segments that do not exceed max_label in length.
    """
    return [encoded[i:i+max_label] for i in range(0, len(encoded), max_label)]

def extract_encoded_request(qname, domain=FIXED_DOMAIN):
    """
    For non-segmented requests, extract the encoded string that has been split from the query name.
    Format: <encoded segments>.<fixed_domain>
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
    The client parses the response metadata based on this format.
    """
    return f"R:{record_id};T:{total};S:{seg};D:{chunk}"

def forward_http_request(http_request):
    """
    Use the partition method to split the HTTP request into header and body parts,
    in order to avoid line-by-line splitting that may break multipart/form-data request body content,
    then use http.client to forward the request to the target server and return the complete response.
    """
    header_part, sep, body = http_request.partition("\r\n\r\n")
    if not header_part:
        return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    header_lines = header_part.split("\r\n")
    request_line = header_lines[0]
    parts = request_line.split()
    if len(parts) < 3:
        return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    method, path, version = parts
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            headers[header_name.strip()] = header_value.strip()
    if "Host" not in headers:
        return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\nMissing Host header"
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
        if method.upper() == "POST":
            # For POST requests, directly convert the body to bytes using latin1 encoding
            body_bytes = body.encode('latin1') if body else None
            conn.request(method, path, body=body_bytes, headers=headers)
        else:
            conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read()
        status_line = f"HTTP/1.1 {response.status} {response.reason}"
        response_headers = ""
        for header, value in response.getheaders():
            response_headers += f"{header}: {value}\r\n"
        full_response = f"{status_line}\r\n{response_headers}\r\n"
        try:
            full_response += response_body.decode('utf-8')
        except:
            full_response += response_body.decode('latin1')
        return full_response
    except Exception as e:
        return f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\nError: {e}"
