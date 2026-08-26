#!/usr/bin/env python3
"""Pure-Python read-only ICS prober (no nmap/Npcap/admin needed).

Scope
- Authorized targets only. Read-only queries. No writes / no control commands.
- Protocols: BACnet/IP (UDP 47808) and Modbus/TCP (502).
- Goal: validate NON-PRODUCTIVE-ICS candidates and reconfirm passive fields live.

BACnet flow
- Send unicast Who-Is -> parse I-Am (device instance + vendor-identifier).
- ReadProperty on Device object for: object-name, vendor-name, model-name,
  vendor-identifier, firmware-revision, application-software-version,
  description, location.

Modbus flow
- Read Device Identification (MEI type 0x0E, function 0x2B) basic + regular objects.

Usage
  py probe_active.py --csv batch1_active_probe_25.csv --out batch1_results.json
  py probe_active.py --ip 1.2.3.4 --bacnet 47808 --modbus 502
"""

import argparse
import csv
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

BACNET_PROPS = {
    "object_name": 77,
    "vendor_name": 121,
    "model_name": 70,
    "vendor_identifier": 120,
    "firmware_revision": 44,
    "application_software_version": 12,
    "description": 28,
    "location": 58,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------- BACnet ----------------

def bacnet_whois(ip, port, timeout=2.5):
    """Unicast Who-Is; return (device_instance, vendor_id, raw_hex) or None."""
    # BVLC: 81 (BACnet/IP), 0a (Original-Unicast-NPDU), length(2)
    # NPDU: 01 00
    # APDU: 10 (unconfirmed-req) 08 (Who-Is)
    apdu = bytes([0x10, 0x08])
    npdu = bytes([0x01, 0x00])
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))
    pkt = bvlc + body

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(1500)
    except Exception as e:
        return {"error": f"whois:{type(e).__name__}"}
    finally:
        s.close()

    return parse_iam(data)


def parse_iam(data):
    raw = data.hex()
    # find APDU: skip BVLC(4) + NPDU(variable). Simplest: locate unconfirmed 0x10 0x00 (I-Am)
    # BVLC header
    if len(data) < 6 or data[0] != 0x81:
        return {"error": "iam:not_bacnet", "raw": raw}
    # NPDU starts at offset 4
    idx = 4
    ver = data[idx]
    ctrl = data[idx + 1]
    idx += 2
    # if destination present (bit 5) skip DNET/DLEN/DADR
    if ctrl & 0x20:
        dnet = data[idx:idx + 2]
        dlen = data[idx + 2]
        idx += 3 + dlen
    # if source present (bit 3) skip SNET/SLEN/SADR
    if ctrl & 0x08:
        slen = data[idx + 2]
        idx += 3 + slen
    # hop count if dest present
    if ctrl & 0x20:
        idx += 1
    # APDU
    apdu = data[idx:]
    if len(apdu) < 2 or apdu[0] != 0x10 or apdu[1] != 0x00:
        return {"error": "iam:not_iam", "raw": raw}
    # I-Am content: object-identifier(device) tag, then unsigned max-apdu, enum seg, unsigned vendor-id
    p = 2
    vals = []
    dev_instance = None
    vendor_id = None
    # object identifier: application tag 12 (0xC4) + 4 bytes
    if p < len(apdu) and apdu[p] == 0xC4:
        objid = struct.unpack(">I", apdu[p + 1:p + 5])[0]
        objtype = objid >> 22
        instance = objid & 0x3FFFFF
        if objtype == 8:
            dev_instance = instance
        p += 5
    # walk remaining application-tagged values
    while p < len(apdu):
        tag = apdu[p]
        tnum = tag >> 4
        lvt = tag & 0x07
        p += 1
        ln = lvt
        if lvt == 5:  # extended length
            ln = apdu[p]
            p += 1
        val = apdu[p:p + ln]
        p += ln
        if tnum == 2:  # unsigned int
            vals.append(int.from_bytes(val, "big"))
    # vendor id is the last unsigned in I-Am
    if vals:
        vendor_id = vals[-1]
    return {"device_instance": dev_instance, "vendor_id": vendor_id, "raw": raw}


def bacnet_read_property(ip, port, device_instance, prop_id, invoke_id=1, timeout=2.5):
    """Confirmed ReadProperty for Device object; return decoded value or error."""
    objid = (8 << 22) | (device_instance & 0x3FFFFF)  # device object type 8
    apdu = bytearray()
    apdu.append(0x00)          # confirmed-request, no segmentation
    apdu.append(0x05)          # max segments/apdu
    apdu.append(invoke_id & 0xFF)
    apdu.append(0x0C)          # service: ReadProperty
    apdu.append(0x0C)          # context tag 0, length 4 (object id)
    apdu += struct.pack(">I", objid)
    # property identifier context tag 1
    if prop_id < 256:
        apdu.append(0x19)      # context tag 1, length 1
        apdu.append(prop_id)
    else:
        apdu.append(0x1A)      # context tag 1, length 2
        apdu += struct.pack(">H", prop_id)

    npdu = bytes([0x01, 0x04, 0x00])  # version, control(expecting reply bit), (no dest)
    # control 0x04 = expecting reply
    npdu = bytes([0x01, 0x04])
    body = npdu + bytes(apdu)
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))
    pkt = bvlc + body

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(1500)
    except Exception as e:
        return {"error": f"rp:{type(e).__name__}"}
    finally:
        s.close()
    return parse_read_property_ack(data)


def parse_read_property_ack(data):
    raw = data.hex()
    if len(data) < 6 or data[0] != 0x81:
        return {"error": "rp:not_bacnet", "raw": raw}
    idx = 4
    ctrl = data[idx + 1]
    idx += 2
    if ctrl & 0x20:
        dlen = data[idx + 2]
        idx += 3 + dlen
    if ctrl & 0x08:
        slen = data[idx + 2]
        idx += 3 + slen
    if ctrl & 0x20:
        idx += 1
    apdu = data[idx:]
    if not apdu:
        return {"error": "rp:empty", "raw": raw}
    # complex-ack = 0x30; error = 0x50; reject 0x60; abort 0x70
    if apdu[0] & 0xF0 == 0x50:
        return {"error": "rp:error_pdu", "raw": raw}
    if apdu[0] & 0xF0 != 0x30:
        return {"error": f"rp:unexpected_pdu_{apdu[0]:02x}", "raw": raw}
    # 0x30 invokeId 0x0C(service) then context tags 0(objid),1(propid),3(opening) value 3(closing)
    p = 2
    if p < len(apdu) and apdu[p] == 0x0C:
        p += 1  # service choice ReadProperty
    # skip context tag 0 objid (0x0C + 4)
    if p < len(apdu) and apdu[p] == 0x0C:
        p += 5
    # skip context tag 1 propid (0x19 +1 or 0x1A +2)
    if p < len(apdu) and apdu[p] == 0x19:
        p += 2
    elif p < len(apdu) and apdu[p] == 0x1A:
        p += 3
    # optional array index context tag 2
    if p < len(apdu) and (apdu[p] & 0xF8) == 0x28:
        ln = apdu[p] & 0x07
        p += 1 + ln
    # opening tag context 3 = 0x3E
    if p < len(apdu) and apdu[p] == 0x3E:
        p += 1
    # now application-tagged value
    return decode_app_value(apdu, p, raw)


def decode_app_value(apdu, p, raw):
    if p >= len(apdu):
        return {"error": "val:none", "raw": raw}
    tag = apdu[p]
    tnum = tag >> 4
    lvt = tag & 0x07
    p += 1
    ln = lvt
    if lvt == 5:
        ln = apdu[p]
        p += 1
    val = apdu[p:p + ln]
    if tnum == 7:  # character string
        if not val:
            return {"value": ""}
        enc = val[0]
        s = val[1:]
        try:
            if enc == 0:
                return {"value": s.decode("utf-8", "replace")}
            elif enc == 4:
                return {"value": s.decode("utf-16-be", "replace")}
            elif enc == 5:
                return {"value": s.decode("latin-1", "replace")}
            else:
                return {"value": s.decode("utf-8", "replace")}
        except Exception:
            return {"value": s.decode("latin-1", "replace")}
    if tnum == 2:  # unsigned
        return {"value": int.from_bytes(val, "big")}
    if tnum == 9:  # enumerated
        return {"value": int.from_bytes(val, "big")}
    return {"value_hex": val.hex(), "tag": tnum}


def probe_bacnet(ip, port):
    out = {"port": port, "ts": now_iso()}
    iam = bacnet_whois(ip, port)
    out["i_am"] = iam
    if not iam or iam.get("error") or iam.get("device_instance") is None:
        return out
    inst = iam["device_instance"]
    props = {}
    inv = 1
    for name, pid in BACNET_PROPS.items():
        r = bacnet_read_property(ip, port, inst, pid, invoke_id=inv)
        inv = (inv + 1) & 0xFF
        props[name] = r.get("value", r.get("value_hex", r.get("error")))
        time.sleep(0.05)
    out["properties"] = props
    return out


# ---------------- Modbus ----------------

def probe_modbus(ip, port, timeout=3.0):
    out = {"port": port, "ts": now_iso()}
    results = {}
    # Read Device Identification: MEI 0x0E, function 0x2B, read device id code 01(basic) then 02(regular)
    for code in (0x01, 0x02):
        # MBAP: transaction(2) protocol(2)=0 length(2) unit(1)
        pdu = bytes([0x2B, 0x0E, code, 0x00])  # function, MEI, readDeviceIdCode, objectId=0
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, len(pdu) + 1, 0x00)
        pkt = mbap + pdu
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(pkt)
            data = s.recv(1024)
            s.close()
        except Exception as e:
            results[f"code{code}"] = {"error": f"{type(e).__name__}"}
            continue
        results[f"code{code}"] = parse_modbus_devid(data)
    out["device_identification"] = results
    return out


def parse_modbus_devid(data):
    raw = data.hex()
    if len(data) < 9:
        return {"error": "short", "raw": raw}
    func = data[7]
    if func == 0x2B + 0x80 or (func & 0x80):
        return {"error": f"exception_{data[8]:02x}", "raw": raw}
    # data[8]=MEI(0x0E), 9=readDevIdCode, 10=conformity, 11=more, 12=nextObjId, 13=numObjects
    try:
        num = data[13]
        p = 14
        objs = {}
        for _ in range(num):
            oid = data[p]; olen = data[p + 1]
            oval = data[p + 2:p + 2 + olen]
            objs[oid] = oval.decode("latin-1", "replace")
            p += 2 + olen
        # standard object ids: 0 vendor,1 product code,2 revision,3 vendorurl,4 productname,5 modelname,6 usertag
        named = {}
        mapping = {0: "vendor_name", 1: "product_code", 2: "revision",
                   3: "vendor_url", 4: "product_name", 5: "model_name", 6: "user_app_name"}
        for k, v in objs.items():
            named[mapping.get(k, f"obj_{k}")] = v
        return {"objects": named, "raw": raw}
    except Exception as e:
        return {"error": f"parse:{type(e).__name__}", "raw": raw}


# ---------------- EIP (EtherNet/IP) ListIdentity ----------------

def probe_eip(ip, port, timeout=3.0):
    out = {"port": port, "ts": now_iso()}
    pkt = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(pkt)
        data = s.recv(1024)
        s.close()
    except Exception as e:
        out["error"] = type(e).__name__
        return out
    out.update(parse_eip_identity(data))
    return out


def parse_eip_identity(data):
    raw = data.hex()
    if len(data) < 24:
        return {"error": "short", "raw": raw}
    p = 24
    try:
        p += 2  # item count
        p += 4  # first item type+length
        p += 2  # protocol version
        p += 16  # sockaddr
        vendor_id = struct.unpack_from("<H", data, p)[0]; p += 2
        device_type = struct.unpack_from("<H", data, p)[0]; p += 2
        product_code = struct.unpack_from("<H", data, p)[0]; p += 2
        rev_major = data[p]; rev_minor = data[p + 1]; p += 2
        p += 2  # status
        serial = struct.unpack_from("<I", data, p)[0]; p += 4
        name_len = data[p]; p += 1
        name = data[p:p + name_len].decode("latin-1", "replace")
        return {"vendor_id": vendor_id, "device_type": device_type,
                "product_code": product_code, "revision": f"{rev_major}.{rev_minor}",
                "serial": f"{serial:08x}", "product_name": name, "raw": raw}
    except Exception as e:
        return {"error": f"parse:{type(e).__name__}", "raw": raw}


# ---------------- S7comm (COTP + SZL read) ----------------

def probe_s7(ip, port, timeout=3.0):
    out = {"port": port, "ts": now_iso()}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102"))
        s.recv(512)
        s.sendall(bytes.fromhex("0300001902f08032010000000000080000f0000001000101e0"))
        s.recv(512)
        s.sendall(bytes.fromhex(
            "0300002102f080320700000000000800080001120411440100ff09000400110000"))
        data = s.recv(1024)
        s.close()
    except Exception as e:
        out["error"] = type(e).__name__
        return out
    out["alive"] = True
    out["szl_raw"] = data.hex()
    runs = []
    cur = b""
    for byte in data:
        if 32 <= byte < 127:
            cur += bytes([byte])
        else:
            if len(cur) >= 4:
                runs.append(cur.decode("latin-1"))
            cur = b""
    if len(cur) >= 4:
        runs.append(cur.decode("latin-1"))
    out["ascii_runs"] = runs
    return out


# ---------------- OPC-UA (Hello + OpenSecureChannel + GetEndpoints) ----------------

def _ua_string(s):
    if s is None:
        return struct.pack("<i", -1)
    b = s.encode("utf-8")
    return struct.pack("<i", len(b)) + b


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = s.recv(n - len(buf))
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_ua_msg(s):
    hdr = _recvn(s, 8)
    if len(hdr) < 8:
        return None
    size = struct.unpack_from("<I", hdr, 4)[0]
    if size < 8 or size > 200000:
        return hdr
    return hdr + _recvn(s, size - 8)


def probe_opcua(ip, port, timeout=4.0):
    out = {"port": port, "ts": now_iso()}
    endpoint = f"opc.tcp://{ip}:{port}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string(endpoint)
        s.sendall(b"HELF" + struct.pack("<I", 8 + len(body)) + body)
        ack = _recv_ua_msg(s)
        if not ack or ack[:3] != b"ACK":
            out["error"] = "no_ack"
            return out
        out["alive"] = True

        sec_uri = "http://opcfoundation.org/UA/SecurityPolicy#None"
        opn_body = _ua_string(sec_uri) + struct.pack("<i", -1) + struct.pack("<i", -1)
        seq = struct.pack("<II", 1, 1)
        typeid = struct.pack("<BBH", 0x01, 0, 446)
        req_header = (b"\x00\x00" + struct.pack("<q", 0) + struct.pack("<I", 0) +
                      struct.pack("<I", 0) + struct.pack("<i", -1) +
                      struct.pack("<I", 0) + b"\x00\x00\x00")
        osc = (req_header + struct.pack("<I", 0) + struct.pack("<I", 0) +
               struct.pack("<I", 1) + struct.pack("<i", -1) + struct.pack("<I", 3600000))
        msg = seq + typeid + osc
        s.sendall(b"OPNF" + struct.pack("<I", 8 + len(opn_body) + len(msg)) + opn_body + msg)
        opn_resp = _recv_ua_msg(s)
        if not opn_resp:
            out["error"] = "no_opn_resp"
            return out
        chan_id, token_id = _parse_opn_token(opn_resp)

        get_body = _build_getendpoints(chan_id, token_id, endpoint)
        s.sendall(get_body)
        ge = _recv_ua_msg(s)
        s.close()
        if not ge:
            out["error"] = "no_getendpoints"
            return out
        out["endpoints_strings"] = _extract_ua_strings(ge)
    except Exception as e:
        out["error"] = type(e).__name__
    return out


def _parse_opn_token(data):
    """Parse (SecureChannelId, TokenId) from an OpenSecureChannelResponse.

    Real OPC UA servers assign a TokenId in the response; subsequent MSG chunks
    must carry it. Sending token_id=0 makes servers silently drop GetEndpoints.
    """
    chan_id = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
    try:
        p = 12  # after 8-byte header + SecureChannelId
        for _ in range(3):  # SecurityPolicyUri, SenderCert, ReceiverCertThumbprint
            ln = struct.unpack_from("<i", data, p)[0]; p += 4
            if ln > 0:
                p += ln
        p += 8  # SequenceHeader: SequenceNumber(4) + RequestId(4)
        enc = data[p]  # response NodeId
        if enc == 0x00:
            p += 2
        elif enc == 0x01:
            p += 4
        else:
            p += 4
        # ResponseHeader: timestamp(8) requestHandle(4) serviceResult(4)
        # serviceDiagnostics(1 empty) stringTable(-1 => 4) additionalHeader extobj(3 null)
        p += 8 + 4 + 4 + 1 + 4 + 3
        p += 4  # ServerProtocolVersion
        p += 4  # ChannelSecurityToken.ChannelId
        token_id = struct.unpack_from("<I", data, p)[0]
        return chan_id, token_id
    except Exception:
        return chan_id, 0


def _build_getendpoints(chan_id, token_id, endpoint):
    typeid = struct.pack("<BBH", 0x01, 0, 428)
    req_header = (b"\x00\x00" + struct.pack("<q", 0) + struct.pack("<I", 0) +
                  struct.pack("<I", 0) + struct.pack("<i", -1) +
                  struct.pack("<I", 0) + b"\x00\x00\x00")
    body = (req_header + _ua_string(endpoint) +
            struct.pack("<i", -1) + struct.pack("<i", -1))
    seq = struct.pack("<II", 2, 2)
    sym = struct.pack("<II", chan_id, token_id)
    inner = seq + typeid + body
    return b"MSGF" + struct.pack("<I", 8 + len(sym) + len(inner)) + sym + inner


def _extract_ua_strings(data):
    out = []
    p = 8
    n = len(data)
    while p + 4 <= n:
        ln = struct.unpack_from("<i", data, p)[0]
        if 3 < ln < 200 and p + 4 + ln <= n:
            chunk = data[p + 4:p + 4 + ln]
            try:
                txt = chunk.decode("utf-8")
                if all(32 <= ord(c) < 127 for c in txt) and any(
                        k in txt.lower() for k in ("urn:", "opc.tcp", "http", "server", "uri", "://")):
                    out.append(txt)
                    p += 4 + ln
                    continue
            except Exception:
                pass
        p += 1
    seen = set(); res = []
    for x in out:
        if x not in seen:
            seen.add(x); res.append(x)
    return res


# ---------------- Driver ----------------

def parse_targets(field):
    """protocol_targets like 'BACNET:47808/udp | MODBUS:502/tcp' -> {'BACNET':47808,'MODBUS':502}"""
    out = {}
    for chunk in [x.strip() for x in field.split("|") if x.strip()]:
        proto, ps = chunk.split(":", 1)
        for p in [x.strip() for x in ps.split(",") if x.strip()]:
            port = int(p.split("/")[0])
            out.setdefault(proto, port)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--out", default="batch1_results.json")
    ap.add_argument("--ip")
    ap.add_argument("--bacnet", type=int)
    ap.add_argument("--modbus", type=int)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--start", type=int, default=0)
    args = ap.parse_args()

    results = []

    if args.ip:
        rec = {"ip": args.ip, "probes": {}}
        if args.bacnet:
            rec["probes"]["BACNET"] = probe_bacnet(args.ip, args.bacnet)
        if args.modbus:
            rec["probes"]["MODBUS"] = probe_modbus(args.ip, args.modbus)
        results.append(rec)
    elif args.csv:
        path = args.csv if os.path.isabs(args.csv) else os.path.join(HERE, args.csv)
        rows = list(csv.DictReader(open(path, encoding="utf-8")))
        if args.start:
            rows = rows[args.start:]
        if args.limit:
            rows = rows[: args.limit]
        for i, r in enumerate(rows, 1):
            ip = r["ip"]
            targets = parse_targets(r.get("protocol_targets", ""))
            rec = {"ip": ip, "score": r.get("score"), "reasons": r.get("reasons"),
                   "as_name": r.get("as_name"), "probes": {}}
            if "BACNET" in targets:
                rec["probes"]["BACNET"] = probe_bacnet(ip, targets["BACNET"])
            if "MODBUS" in targets:
                rec["probes"]["MODBUS"] = probe_modbus(ip, targets["MODBUS"])
            if "EIP" in targets:
                rec["probes"]["EIP"] = probe_eip(ip, targets["EIP"])
            if "S7" in targets:
                rec["probes"]["S7"] = probe_s7(ip, targets["S7"])
            if "OPC_UA" in targets:
                rec["probes"]["OPC_UA"] = probe_opcua(ip, targets["OPC_UA"])
            results.append(rec)
            print(f"[{i}/{len(rows)}] {ip} done")
    else:
        ap.error("provide --csv or --ip")

    out_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    json.dump(results, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"WROTE {out_path} ({len(results)} hosts)")


if __name__ == "__main__":
    main()
