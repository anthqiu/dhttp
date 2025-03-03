"""
server.py
---------
DNS Tunnel server code, handling client requests and forwarding HTTP requests.
"""

import socket
import threading
import base64
import uuid
import time
from dnslib import DNSRecord, QTYPE, RR, TXT
from utils import UDP_PORT, FIXED_DOMAIN, split_txt, split_encoded, extract_encoded_request, format_txt_response, forward_http_request

# Used to store HTTP response segmentation records: record_id -> (list of chunks, creation time)
records = {}
records_lock = threading.Lock()

# Used to store client segmented request data: record_id -> {"total": int, "received": {seg_index: data}, "timestamp": float}
incoming_requests = {}
incoming_requests_lock = threading.Lock()

RECORD_EXPIRE = 300  # Record validity period (seconds); automatic cleanup is not implemented in this example

def process_request_segment(dns_record, addr, sock):
    """
    Process a single segment in a client's segmented request.
    Format: n.<record_id>.<seg_index>.<total_segments>.<data_chunk>.<fixed_domain>
    Save this segment into incoming_requests and reply with an ACK.
    """
    qname = str(dns_record.q.qname)
    if qname.endswith('.'):
        qname = qname[:-1]
    labels = qname.split('.')
    if len(labels) < 6:
        print("Segmented request format error:", qname)
        return
    record_id = labels[1]
    try:
        seg_index = int(labels[2])
        total_segments = int(labels[3])
    except Exception as e:
        print("Error parsing segment index/total segments in segmented request:", e)
        return
    data_chunk = labels[4]  # Use the 5th label as the data chunk
    with incoming_requests_lock:
        if record_id not in incoming_requests:
            incoming_requests[record_id] = {"total": total_segments, "received": {}, "timestamp": time.time()}
        entry = incoming_requests[record_id]
        if entry["total"] != total_segments:
            print("Total segments received do not match the existing record:", qname)
            return
        entry["received"][seg_index] = data_chunk
    ack_txt = f"ACK:{record_id}:{seg_index}"
    reply = dns_record.reply()
    reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(ack_txt), ttl=60))
    sock.sendto(reply.pack(), addr)
    print(f"Received request segment {seg_index}/{total_segments}, Record ID={record_id}")

def process_request_trigger(dns_record, addr, sock):
    """
    Process a client trigger query, format: s.<record_id>.<fixed_domain>
    Check if all segments have been received, assemble the complete request,
    forward it, and return the first response segment.
    """
    qname = str(dns_record.q.qname)
    if qname.endswith('.'):
        qname = qname[:-1]
    labels = qname.split('.')
    if len(labels) < 3 or labels[0] != "s":
        print("Trigger query format error:", qname)
        return
    record_id = labels[1]
    with incoming_requests_lock:
        if record_id not in incoming_requests:
            resp_txt = f"Error: Request record {record_id} not found"
            reply = dns_record.reply()
            reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(resp_txt), ttl=60))
            sock.sendto(reply.pack(), addr)
            return
        entry = incoming_requests[record_id]
        if len(entry["received"]) != entry["total"]:
            resp_txt = f"Error: Request record {record_id} is incomplete"
            reply = dns_record.reply()
            reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(resp_txt), ttl=60))
            sock.sendto(reply.pack(), addr)
            return
        segments = [entry["received"][i] for i in sorted(entry["received"].keys())]
        full_encoded = "".join(segments)
        missing_padding = len(full_encoded) % 8
        if missing_padding:
            full_encoded += '=' * (8 - missing_padding)
        try:
            http_request = base64.b32decode(full_encoded.encode('utf-8')).decode('utf-8')
        except Exception as e:
            http_request = f"Decoding failed: {e}"
    print(f"Assembled complete request record {record_id}, HTTP request:\n{http_request}")
    response_text = forward_http_request(http_request)
    print(f"HTTP response after forwarding request:\n{response_text}")
    chunks = split_txt(response_text, max_length=200)
    total_segments = len(chunks)
    response_record_id = uuid.uuid4().hex
    with records_lock:
        records[response_record_id] = (chunks, time.time())
    txt_str = format_txt_response(response_record_id, total_segments, 0, chunks[0])
    reply = dns_record.reply()
    reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(txt_str), ttl=60))
    sock.sendto(reply.pack(), addr)

def process_new_request(dns_record, addr, sock):
    """
    Process a non-segmented new request (when the request is short and directly encoded in the query name).
    """
    qname = str(dns_record.q.qname)
    if qname.endswith('.'):
        qname = qname[:-1]
    encoded_request = extract_encoded_request(qname, domain=FIXED_DOMAIN)
    if not encoded_request:
        print("Unable to extract encoded content, query name format error:", qname)
        return
    try:
        missing_padding = len(encoded_request) % 8
        if missing_padding:
            encoded_request += '=' * (8 - missing_padding)
        http_request = base64.b32decode(encoded_request.encode('utf-8')).decode('utf-8')
    except Exception as e:
        http_request = f"Decoding failed: {e}"
    print(f"Received HTTP request from {addr}:\n{http_request}")
    response_text = forward_http_request(http_request)
    print(f"HTTP response after forwarding request:\n{response_text}")
    chunks = split_txt(response_text, max_length=200)
    total_segments = len(chunks)
    response_record_id = uuid.uuid4().hex
    with records_lock:
        records[response_record_id] = (chunks, time.time())
    txt_str = format_txt_response(response_record_id, total_segments, 0, chunks[0])
    reply = dns_record.reply()
    reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(txt_str), ttl=60))
    sock.sendto(reply.pack(), addr)

def process_retrieval_request(dns_record, addr, sock):
    """
    Process a response retrieval request, format: r.<response_record_id>.<seg>.<fixed_domain>
    Return the corresponding segment data.
    """
    qname = str(dns_record.q.qname)
    if qname.endswith('.'):
        qname = qname[:-1]
    labels = qname.split('.')
    if len(labels) < 3 or labels[0] != "r":
        print("Retrieval query format error:", qname)
        return
    record_id = labels[1]
    try:
        seg = int(labels[2])
    except Exception as e:
        print("Error parsing segment number:", e)
        return
    with records_lock:
        if record_id not in records:
            txt_str = f"Error: Record {record_id} not found"
        else:
            chunks, ts = records[record_id]
            total_segments = len(chunks)
            if seg < 0 or seg >= total_segments:
                txt_str = f"Error: Segment {seg} out of range"
            else:
                txt_str = format_txt_response(record_id, total_segments, seg, chunks[seg])
    reply = dns_record.reply()
    reply.add_answer(RR(dns_record.q.qname, QTYPE.TXT, rdata=TXT(txt_str), ttl=60))
    sock.sendto(reply.pack(), addr)

def process_query(data, addr, sock):
    """
    Determine the request type based on the query name:
      - Segmented request: prefix "n"
      - Trigger query (to assemble segmented request): prefix "s"
      - Response retrieval: prefix "r"
      - Non-segmented new request: all other cases
    """
    try:
        dns_record = DNSRecord.parse(data)
    except Exception as e:
        print("Failed to parse DNS request:", e)
        return
    qname = str(dns_record.q.qname)
    labels = qname.split('.')
    if labels[0] == "r":
        process_retrieval_request(dns_record, addr, sock)
    elif labels[0] == "n":
        process_request_segment(dns_record, addr, sock)
    elif labels[0] == "s":
        process_request_trigger(dns_record, addr, sock)
    else:
        process_new_request(dns_record, addr, sock)

def run_server():
    """
    Start the UDP server, continuously listening and processing each DNS request in a new thread.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', UDP_PORT))
    print(f"HTTP over DNS server started, listening on port {UDP_PORT} ...")
    while True:
        try:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=process_query, args=(data, addr, sock)).start()
        except Exception as e:
            print("Server error:", e)

if __name__ == '__main__':
    run_server()
