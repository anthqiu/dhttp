#!/usr/bin/env python3
"""
client.py
---------
DNS Tunnel client code, supporting GET and POST (single file upload) requests,
with optional segmented sending. The client constructs an HTTP request (as a byte array)
and sends it through a DNS tunnel, then receives and reassembles the response from the target server.
HTTP headers are parsed, but the body is treated as raw bytes.
"""

import socket
import base64
import sys
import uuid
from dnslib import DNSRecord, QTYPE, RR, TXT
from urllib.parse import urlparse
from utils import UDP_PORT, FIXED_DOMAIN, split_encoded

def parse_host_header(url):
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError("Currently only the http protocol is supported")
    host = parsed.hostname
    if parsed.port:
        host_header = f"{host}:{parsed.port}"
    else:
        host_header = host
    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query
    return path, host_header

def construct_http_request_from_url(url):
    """
    Construct an HTTP GET request from the URL (only supports http).
    If the URL specifies a port, include it in the Host header.
    Returns a byte array.
    """
    path, host_header = parse_host_header(url)
    request_str = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request_str.encode('ascii')

def construct_post_request(url, file_path):
    """
    Construct an HTTP POST request given the URL and file path.
    Uploads the file using multipart/form-data format (field name is "file").
    The file content is kept as raw bytes.
    If the URL specifies a port, include it in the Host header.
    Returns a byte array.
    """
    boundary = b"--qhurc--qshi-AT-vt-edu-HNioOvfZCqwPnD3He8PuoD"
    path, host_header = parse_host_header(url)
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception as e:
        raise ValueError(f"Failed to read file: {e}")
    filename = file_path.split("/")[-1]
    CRLF = b"\r\n"
    body_lines = [
        b"--" + boundary,
        f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode('ascii'),
        b"Content-Type: text/plain",
        b"",
        file_data,
        b"--" + boundary + b"--",
        b""
    ]
    body = CRLF.join(body_lines)
    content_length = len(body)
    request_lines = [
        f"POST {path} HTTP/1.1".encode('ascii'),
        f"Host: {host_header}".encode('ascii'),
        b"User-Agent: curl/8.12.1",
        b"Accept: */*",
        f"Content-Length: {content_length}".encode('ascii'),
        f"Content-Type: multipart/form-data; boundary={boundary.decode('ascii')}".encode('ascii'),
        b"",
        b""
    ]
    header = CRLF.join(request_lines)
    return header + body

def send_request(http_request_bytes, server_ip, server_port=UDP_PORT, domain=FIXED_DOMAIN):
    """
    Non-segmented request:
    Base32-encode the HTTP request bytes and split it into labels,
    then construct a DNS query and send it to the server.
    The server returns a Base32-encoded HTTP response which is reassembled and decoded.
    Returns the complete HTTP response as a byte array.
    """
    encoded = base64.b32encode(http_request_bytes).decode('ascii').rstrip('=')
    labels = split_encoded(encoded, max_label=50)
    query_name = ".".join(labels + [domain])
    dns_request = DNSRecord.question(query_name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    full_encoded_response = ""
    try:
        sock.sendto(dns_request.pack(), (server_ip, server_port))
        data, _ = sock.recvfrom(4096)
        response = DNSRecord.parse(data)
        txt_str = None
        for rr in response.rr:
            if rr.rtype == QTYPE.TXT:
                if hasattr(rr.rdata, 'data'):
                    txt_str = b" ".join(rr.rdata.data).decode('ascii')
                elif hasattr(rr.rdata, 'strings'):
                    txt_str = b" ".join(rr.rdata.strings).decode('ascii')
                break
        if not txt_str:
            print("Did not receive TXT data")
            return
        meta = {}
        for item in txt_str.split(';'):
            if ':' in item:
                k, v = item.split(':', 1)
                meta[k.strip()] = v.strip()
        response_record_id = meta.get('R')
        total = int(meta.get('T', '1'))
        seg = int(meta.get('S', '0'))
        data_chunk = meta.get('D', '')
        full_encoded_response += data_chunk
        print(f"Received segment {seg + 1}/{total}, Record ID={response_record_id}")
        for seg_index in range(1, total):
            retrieval_qname = f"r.{response_record_id}.{seg_index}.{domain}"
            dns_req = DNSRecord.question(retrieval_qname)
            sock.sendto(dns_req.pack(), (server_ip, server_port))
            data, _ = sock.recvfrom(4096)
            resp = DNSRecord.parse(data)
            txt_str = None
            for rr in resp.rr:
                if rr.rtype == QTYPE.TXT:
                    if hasattr(rr.rdata, 'data'):
                        txt_str = b" ".join(rr.rdata.data).decode('ascii')
                    elif hasattr(rr.rdata, 'strings'):
                        txt_str = b" ".join(rr.rdata.strings).decode('ascii')
                    break
            if not txt_str:
                print(f"Segment {seg_index} did not receive data")
                continue
            meta = {}
            for item in txt_str.split(';'):
                if ':' in item:
                    k, v = item.split(':', 1)
                    meta[k.strip()] = v.strip()
            full_encoded_response += meta.get('D', '')
            print(f"Received segment {seg_index + 1}/{total}")
        full_response_bytes = base64.b32decode(full_encoded_response.encode('ascii'))
        print("Complete HTTP response (bytes):")
        print(full_response_bytes)
        return full_response_bytes
    except socket.timeout:
        print("Request timed out, did not receive a response.")
    except Exception as e:
        print("Error occurred during the request:", e)

def send_segmented_request(http_request_bytes, server_ip, server_port=UDP_PORT, domain=FIXED_DOMAIN):
    """
    Segmented request sending:
      1. Base32-encode the HTTP request bytes and split it into multiple segments.
      2. Send each segment separately (format: n.<record_id>.<seg_index>.<total_segments>.<data_chunk>.<domain>), waiting for ACK.
      3. Send a trigger query: s.<record_id>.<domain> to obtain the first response segment.
      4. Retrieve subsequent response segments based on metadata and reassemble the complete HTTP response.
    Returns the complete HTTP response as a byte array.
    """
    encoded = base64.b32encode(http_request_bytes).decode('ascii').rstrip('=')
    segments = split_encoded(encoded, max_label=50)
    total_segments = len(segments)
    record_id = uuid.uuid4().hex
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    for seg_index, chunk in enumerate(segments):
        qname = f"n.{record_id}.{seg_index}.{total_segments}.{chunk}.{domain}"
        dns_req = DNSRecord.question(qname)
        try:
            sock.sendto(dns_req.pack(), (server_ip, server_port))
            data, _ = sock.recvfrom(512)
            # ACK parsing can be implemented here (omitted)
        except socket.timeout:
            print(f"Segment {seg_index} ACK timed out")
    print(f"All {total_segments} request segments sent, Record ID={record_id}")
    trigger_qname = f"s.{record_id}.{domain}"
    dns_req = DNSRecord.question(trigger_qname)
    full_encoded_response = ""
    try:
        sock.sendto(dns_req.pack(), (server_ip, server_port))
        data, _ = sock.recvfrom(4096)
        response = DNSRecord.parse(data)
        txt_str = None
        for rr in response.rr:
            if rr.rtype == QTYPE.TXT:
                if hasattr(rr.rdata, 'data'):
                    txt_str = b" ".join(rr.rdata.data).decode('ascii')
                elif hasattr(rr.rdata, 'strings'):
                    txt_str = b" ".join(rr.rdata.strings).decode('ascii')
                break
        if not txt_str:
            print("Trigger query did not receive TXT data")
            return
        meta = {}
        for item in txt_str.split(';'):
            if ':' in item:
                k, v = item.split(':', 1)
                meta[k.strip()] = v.strip()
        response_record_id = meta.get('R')
        total_resp = int(meta.get('T', '1'))
        seg = int(meta.get('S', '0'))
        data_chunk = meta.get('D', '')
        full_encoded_response += data_chunk
        print(f"Received response segment {seg + 1}/{total_resp}, Record ID={response_record_id}")
        for seg_index in range(1, total_resp):
            retrieval_qname = f"r.{response_record_id}.{seg_index}.{domain}"
            dns_req = DNSRecord.question(retrieval_qname)
            sock.sendto(dns_req.pack(), (server_ip, server_port))
            data, _ = sock.recvfrom(4096)
            resp = DNSRecord.parse(data)
            txt_str = None
            for rr in resp.rr:
                if rr.rtype == QTYPE.TXT:
                    if hasattr(rr.rdata, 'data'):
                        txt_str = b" ".join(rr.rdata.data).decode('ascii')
                    elif hasattr(rr.rdata, 'strings'):
                        txt_str = b" ".join(rr.rdata.strings).decode('ascii')
                    break
            if not txt_str:
                print(f"Response segment {seg_index} did not receive data")
                continue
            meta = {}
            for item in txt_str.split(';'):
                if ':' in item:
                    k, v = item.split(':', 1)
                    meta[k.strip()] = v.strip()
            full_encoded_response += meta.get('D', '')
            print(f"Received response segment {seg_index + 1}/{total_resp}")
        full_response_bytes = base64.b32decode(full_encoded_response.encode('ascii'))
        print("Complete HTTP response (bytes):")
        print(full_response_bytes)
        return full_response_bytes
    except socket.timeout:
        print("Trigger query or response retrieval timed out")
    except Exception as e:
        print("Error occurred during the request:", e)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  GET request: python client.py <server_ip> <http_request|url> [--segmented]")
        print("  POST request: python client.py <server_ip> --post <url> <file_path> [--segmented]")
        sys.exit(1)

    server_ip = sys.argv[1]
    if "--post" in sys.argv:
        post_index = sys.argv.index("--post")
        if len(sys.argv) <= post_index + 2:
            print("Usage for POST: python client.py <server_ip> --post <url> <file_path> [--segmented]")
            sys.exit(1)
        url = sys.argv[post_index + 1]
        file_path = sys.argv[post_index + 2]
        try:
            http_request_bytes = construct_post_request(url, file_path)
        except Exception as e:
            print("Failed to construct POST request:", e)
            sys.exit(1)
    else:
        input_str = sys.argv[2]
        if input_str.startswith("http://") or input_str.startswith("https://"):
            try:
                http_request_bytes = construct_http_request_from_url(input_str)
            except Exception as e:
                print("Failed to parse URL or construct request:", e)
                sys.exit(1)
        else:
            # For manual input, treat it as ASCII and convert to bytes
            http_request_bytes = input_str.encode('ascii')

    send_segmented_request(http_request_bytes, server_ip)
