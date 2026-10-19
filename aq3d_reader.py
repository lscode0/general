#!/usr/bin/env python3
"""AQ3D (SmartFoxServer 2X) packet reader.
Usage:
  python aq3d_reader.py capture.bin [--xor] [--show-hex]
  python aq3d_reader.py capture.pcap [--port 9933]
  python aq3d_reader.py --hex "80004312..."  (decode single packet)
  python aq3d_reader.py --live <host> <port> (passive TCP dump via proxy-style tap is out of scope; connects and dumps S2C)

Handles: S2C framing 0x80/0x88/0xA0, C2S 0xC4/0xE4 with XOR + server_id,
zlib payloads, full SFSObject/SFSArray type system (ids 0-18 + 19-29 typed arrays).
"""
import argparse, struct, sys, zlib

# --- SFS data types ---
T_NULL=0; T_BOOL=1; T_BYTE=2; T_SHORT=3; T_INT=4; T_LONG=5; T_FLOAT=6; T_DOUBLE=7
T_UTF=8; T_BOOL_ARR=9; T_BYTE_ARR=10; T_SHORT_ARR=11; T_INT_ARR=12; T_LONG_ARR=13
T_FLOAT_ARR=14; T_DOUBLE_ARR=15; T_UTF_ARR=16; T_SFS_ARR=17; T_SFS_OBJ=18

class R:
    def __init__(s,b,off=0): s.b=b; s.o=off
    def u8(s): v=s.b[s.o]; s.o+=1; return v
    def u16(s): v=struct.unpack_from('>H',s.b,s.o)[0]; s.o+=2; return v
    def i16(s): v=struct.unpack_from('>h',s.b,s.o)[0]; s.o+=2; return v
    def u32(s): v=struct.unpack_from('>I',s.b,s.o)[0]; s.o+=4; return v
    def i32(s): v=struct.unpack_from('>i',s.b,s.o)[0]; s.o+=4; return v
    def i64(s): v=struct.unpack_from('>q',s.b,s.o)[0]; s.o+=8; return v
    def f32(s): v=struct.unpack_from('>f',s.b,s.o)[0]; s.o+=4; return v
    def f64(s): v=struct.unpack_from('>d',s.b,s.o)[0]; s.o+=8; return v
    def raw(s,n): v=s.b[s.o:s.o+n]; s.o+=n; return bytes(v)
    def utf(s):
        n=s.u16(); return s.raw(n).decode('utf-8',errors='replace')

def dec_val(r,t):
    if t==T_NULL: return None
    if t==T_BOOL: return bool(r.u8())
    if t==T_BYTE: return r.u8()
    if t==T_SHORT: return r.i16()
    if t==T_INT: return r.i32()
    if t==T_LONG: return r.i64()
    if t==T_FLOAT: return r.f32()
    if t==T_DOUBLE: return r.f64()
    if t==T_UTF: return r.utf()
    if t==T_BOOL_ARR: return [bool(r.u8()) for _ in range(r.u16())]
    if t==T_BYTE_ARR: n=r.u32(); return r.raw(n)
    if t==T_SHORT_ARR: return [r.i16() for _ in range(r.u16())]
    if t==T_INT_ARR: return [r.i32() for _ in range(r.u16())]
    if t==T_LONG_ARR: return [r.i64() for _ in range(r.u16())]
    if t==T_FLOAT_ARR: return [r.f32() for _ in range(r.u16())]
    if t==T_DOUBLE_ARR: return [r.f64() for _ in range(r.u16())]
    if t==T_UTF_ARR: return [r.utf() for _ in range(r.u16())]
    if t==T_SFS_ARR: return dec_arr(r)
    if t==T_SFS_OBJ: return dec_obj(r)
    # SFS2X 2.13+ / AQ3D custom: 19=INT_OBJ? treat generically
    if 19<=t<=29:  # typed object wrappers: read as SFSObject then tag
        return {"_type":t,"_obj":dec_obj(r)}
    raise ValueError(f"bad type {t} at off {r.o}")

def dec_obj(r):
    n=r.u16(); o={}
    for _ in range(n):
        k=r.utf(); t=r.u8(); o[k]=(t,dec_val(r,t))
    return o

def dec_arr(r):
    n=r.u16(); return [(t:=r.u8(),dec_val(r,t)) for _ in range(n)]

def fmt(o,ind=0):
    p='  '*ind
    if isinstance(o,dict) and o and isinstance(next(iter(o.values())),tuple):
        L=[]
        for k,(t,v) in o.items():
            L.append(f"{p}{k} (t{t}): {fmt(v,ind+1) if isinstance(v,(dict,list)) else repr(v)}")
        return '\n'.join(L)
    if isinstance(o,dict): return '\n'.join(f"{p}{k}: {fmt(v,ind+1)}" for k,v in o.items()) or '{}'
    if isinstance(o,list):
        return '\n'.join(f"{p}- {fmt((v[1] if isinstance(v,tuple) else v),ind+1) if isinstance((v[1] if isinstance(v,tuple) else v),(dict,list)) else repr(v)}" for v in o) or '[]'
    if isinstance(o,bytes): return f"<{len(o)} bytes> {o[:64].hex()}{'...' if len(o)>64 else ''}"
    return repr(o)

def summarize(root):
    try:
        c=root.get('c'); a=root.get('a'); p=root.get('p')
        cv=c[1] if c else '?'; av=a[1] if a else '?'
        s=f"c={cv} a={av}"
        if cv==1 and av==13 and p:
            pp=p[1]; cmd=pp.get('c'); rid=pp.get('r')
            s+=f" cmd={cmd[1] if cmd else '?'} room={rid[1] if rid else '?'}"
        return s
    except Exception: return '?'

def xor_decode(data,size):
    key=bytes([size&0xFF,(size>>8)&0xFF,0,0])
    return bytes(b^key[i%4] for i,b in enumerate(data))

def split_stream(buf):
    """Yield (marker, payload_bytes, total_consumed, info). Handles S2C + C2S."""
    i=0; n=len(buf)
    while i<n:
        m=buf[i]
        if m&0x80==0:  # not SFS binary marker -> resync 1 byte
            i+=1; continue
        big=m&0x08; comp=m&0x20; enc=m&0x40
        # C2S has extra 2B server_id before length: markers 0xC0-0xEF range
        c2s = (m&0xC0)==0xC0
        try:
            if c2s:
                if i+5>n: break
                sid=struct.unpack_from('>H',buf,i+1)[0]
                ln=struct.unpack_from('>H',buf,i+3)[0]
                hdr=5; info=f"C2S sid={sid}"
            elif big:
                if i+5>n: break
                ln=struct.unpack_from('>I',buf,i+1)[0]; hdr=5; info="S2C-big"
            else:
                if i+3>n: break
                ln=struct.unpack_from('>H',buf,i+1)[0]; hdr=3; info="S2C"
            if i+hdr+ln>n: break  # incomplete
            pay=bytes(buf[i+hdr:i+hdr+ln])
            if c2s:
                # try XOR (key derived from size); detect by checking first bytes decode as SFSObject
                x=xor_decode(pay,ln)
                pay=x; info+=" xor"
            if comp:
                try: pay=zlib.decompress(pay); info+=" zlib"
                except Exception as e: info+=f" zlibFAIL:{e}"
            yield m,pay,hdr+ln,info+(f" enc" if enc else "")
            i+=hdr+ln
        except struct.error: break

def decode_payload(pay):
    r=R(pay)
    try: return dec_obj(r), r.o
    except Exception as e: return {"_error":str(e),"hex":pay.hex()}, 0

def handle_buffer(buf,show_hex=False):
    for idx,(m,pay,ln,info) in enumerate(split_stream(buf)):
        print(f"--- pkt#{idx} marker=0x{m:02X} len={len(pay)} [{info}]")
        if show_hex: print(f"  raw: {pay[:256].hex()}")
        obj,used=decode_payload(pay)
        if "_error" in obj: print(f"  DECODE FAIL: {obj}")
        else:
            print(f"  [{summarize(obj)}] (consumed {used}/{len(pay)})")
            print(fmt(obj,1))
        print()

def read_pcap(path,port=9933):
    import struct as S
    d=open(path,'rb').read()
    magic=S.unpack('<I',d[:4])[0]
    be=magic==0xA1B2C3D4; bo='>' if be else '<'
    if magic not in (0xA1B2C3D4,0xD4C3B2A1): raise SystemExit("not a classic pcap (no pcapng support)")
    o=24; c2s_buf=bytearray(); s2c_buf=bytearray(); pkts=0
    while o+16<=len(d):
        ts1,ts2,il,ol=S.unpack(bo+'IIII',d[o:o+16]); o+=16
        pkt=d[o:o+il]; o+=il; pkts+=1
        if len(pkt)<42: continue
        ihl=(pkt[14]&0xF)*4
        if pkt[14]>>4!=4 or pkt[23]!=6: continue
        sp,dp=S.unpack('>HH',pkt[34:38])
        base=14+ihl+20
        if sp==port: s2c_buf+=pkt[base:]
        elif dp==port: c2s_buf+=pkt[base:]
    print(f"# pcap: {pkts} frames | C2S {len(c2s_buf)}B S2C {len(s2c_buf)}B (port {port})")
    if c2s_buf: print("== CLIENT -> SERVER =="); handle_buffer(bytes(c2s_buf))
    if s2c_buf: print("== SERVER -> CLIENT =="); handle_buffer(bytes(s2c_buf))

def main():
    ap=argparse.ArgumentParser(description="AQ3D packet reader")
    ap.add_argument('file',nargs='?')
    ap.add_argument('--hex',help='decode single hex string')
    ap.add_argument('--port',type=int,default=9933)
    ap.add_argument('--show-hex',action='store_true')
    ap.add_argument('--live',nargs=2,metavar=('HOST','PORT'),help='connect and dump S2C stream')
    a=ap.parse_args()
    if a.hex:
        handle_buffer(bytes.fromhex(a.hex.replace(' ','')),a.show_hex); return
    if a.live:
        import socket
        s=socket.create_connection((a.live[0],int(a.live[1]))); s.settimeout(10)
        print(f"# live tap {a.live[0]}:{a.live[1]} (10s) ...")
        buf=b''
        try:
            while True: buf+=s.recv(65536)
        except socket.timeout: pass
        handle_buffer(buf,a.show_hex); return
    if not a.file: ap.error("need file, --hex or --live")
    if a.file.endswith(('.pcap',)): read_pcap(a.file,a.port)
    else: handle_buffer(open(a.file,'rb').read(),a.show_hex)

if __name__=='__main__': main()
