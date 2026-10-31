"""Scoped nftables packet marking and HTB/FQ-CoDel egress scheduling.

No routing, DHCP, NAT or NetworkManager mutations. Marks use bits 16..23 only.
Table name and qdisc handle are reserved and ownership checked before removal.
"""
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

TABLE="edgeqos"
HANDLE="e100:"
MARKS={"realtime":0x000a0000,"interactive":0x00140000,"best_effort":0x001e0000,"bulk":0x00280000}
# queue name, HTB minor handle, guaranteed share of the link, strict priority
SHARES=(("realtime",10,.20,0),("interactive",20,.30,1),("best_effort",30,.30,2),("bulk",40,.20,3))


def floors(rate):
    """Guaranteed Mbit/s per queue at a given link rate; the starvation reference."""
    return {name: round(float(rate)*fraction,3) for name,_minor,fraction,_prio in SHARES}


def run(args, text=None, check=True):
    p=subprocess.run(args,input=text,text=True,capture_output=True,timeout=15)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} failed: {p.stderr.strip()}")
    return p


def validate(c):
    for k in ("uplink","downlink"):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}",c[k]): raise ValueError("Invalid interface")
    if c["uplink"]==c["downlink"]: raise ValueError("Interfaces must differ")
    net=ipaddress.ip_network(c["lan"])
    if net.version!=4 or ipaddress.ip_address(c["gateway"]) not in net: raise ValueError("Invalid IPv4 LAN")
    for k in ("upload_mbit","download_mbit"):
        if not 1<=float(c[k])<=900: raise ValueError("Rate outside 1..900 Mbit/s")
    if c["mode"] not in ("monitor","enforce"): raise ValueError("Invalid mode")
    if not 32<=c["max_flows"]<=4096 or not 1<=c["interval"]<=10 or not 5<=c["idle_seconds"]<=120:
        raise ValueError("Flow/interval bounds exceeded")
    if not .5<=c["confidence"]<=1 or c["listen"] not in ("127.0.0.1",c["gateway"],"0.0.0.0"):
        raise ValueError("Invalid confidence or listen address")
    if not 1024<=c["port"]<=65535: raise ValueError("Invalid port")
    admins=c.get('control_clients',['127.0.0.1'])
    if not isinstance(admins,list) or len(admins)>8: raise ValueError('Invalid control clients')
    for client in admins:
        addr=ipaddress.ip_address(client)
        if addr.version!=4 or not addr.is_private or addr.is_unspecified or addr.is_multicast:
            raise ValueError('Control clients must be specific local IPv4 addresses')


class Policy:
    def __init__(self,c):
        validate(c); self.c=c; self.state=Path(c["state_dir"])/"policy.json"

    def qdiscs(self,dev):
        return json.loads(run(["tc","-j","qdisc","show","dev",dev]).stdout)

    def nft_base(self):
        c=self.c
        text = f'''table inet {TABLE} {{
 comment "Tata EdgeQoS owned v1"
 map flows {{ type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service : verdict; flags timeout; timeout 15s; size 4096; }}
 chain class_realtime {{ meta mark set (meta mark & 0xff00ffff) | 0x000a0000 counter; }}
 chain class_interactive {{ meta mark set (meta mark & 0xff00ffff) | 0x00140000 counter; }}
 chain class_best_effort {{ meta mark set (meta mark & 0xff00ffff) | 0x001e0000 counter; }}
 chain class_bulk {{ meta mark set (meta mark & 0xff00ffff) | 0x00280000 counter; }}
 chain classify {{ type filter hook forward priority -140; policy accept;
  iifname "{c['downlink']}" oifname "{c['uplink']}" ip saddr {c['lan']} meta l4proto {{ tcp, udp }} ip saddr . ip daddr . meta l4proto . th sport . th dport vmap @flows
  iifname "{c['uplink']}" oifname "{c['downlink']}" ip daddr {c['lan']} meta l4proto {{ tcp, udp }} ip daddr . ip saddr . meta l4proto . th dport . th sport vmap @flows
 }}
}}\n'''

        if self.c.get("scheduler")=="cake":
            for old,new in (("0x000a0000","0x00040000"),("0x00140000","0x00030000"),("0x001e0000","0x00020000"),("0x00280000","0x00010000")):
                text=text.replace(old,new)
        if self.c.get("scheduler")=="cake" and not self.c.get("cake_ai",True):
            for mark in ("0x00040000","0x00030000","0x00010000"):
                text=text.replace(mark,"0x00020000")
        return text

    def setup(self):
        if self.state.exists(): raise RuntimeError("Policy state exists: rollback first")
        if run(["nft","list","table","inet",TABLE],check=False).returncode==0:
            raise RuntimeError("Reserved nft table already exists; refusing takeover")
        baseline={}
        for dev in (self.c["uplink"],self.c["downlink"]):
            qs=self.qdiscs(dev); roots=[q for q in qs if q.get("root")]
            if len(roots)!=1 or roots[0]["kind"] not in ("mq","pfifo_fast","fq_codel","noqueue") or roots[0].get("handle")!="0:":
                raise RuntimeError(f"{dev}: custom qdisc detected; refusing overwrite")
            if any(q.get("handle")!="0:" for q in qs):
                raise RuntimeError(f"{dev}: existing traffic controls detected")
            if run(["tc","filter","show","dev",dev,"root"]).stdout.strip():
                raise RuntimeError(f"{dev}: existing filters detected")
            baseline[dev]=roots[0]["kind"]
        # Syntax validation occurs before changing any kernel state.
        run(["nft","-c","-f","-"],self.nft_base())
        self.state.parent.mkdir(parents=True,exist_ok=True)
        self.state.write_text(json.dumps({"version":1,"baseline":baseline}))
        try:
            for dev,rate in ((self.c["uplink"],self.c["upload_mbit"]),(self.c["downlink"],self.c["download_mbit"])):
                if self.c.get("scheduler")=="cake":
                    run(["tc","qdisc","replace","dev",dev,"root","handle",HANDLE,"cake","bandwidth",f"{rate}mbit",("diffserv4" if self.c.get("cake_ai",True) else "besteffort"),"nat","triple-isolate","fwmark","0xff0000","memlimit","16mb"])
                    continue
                if not self.c.get("htb_ai",True):
                    # One shaped class, one FQ-CoDel queue: the classic HTB+FQ-CoDel
                    # shaper, the counterpart to CAKE besteffort for A/B comparison.
                    run(["tc","qdisc","replace","dev",dev,"root","handle",HANDLE,"htb","default","30"])
                    run(["tc","class","add","dev",dev,"parent",HANDLE,"classid","e100:1","htb","rate",f"{rate}mbit","ceil",f"{rate}mbit"])
                    run(["tc","class","add","dev",dev,"parent","e100:1","classid","e100:30","htb","rate",f"{rate}mbit","ceil",f"{rate}mbit","prio","0"])
                    run(["tc","qdisc","add","dev",dev,"parent","e100:30","handle","30:","fq_codel","limit","512","target","5ms","interval","100ms","memory_limit","1Mb"])
                    continue
                run(["tc","qdisc","replace","dev",dev,"root","handle",HANDLE,"htb","default","30"])
                run(["tc","class","add","dev",dev,"parent",HANDLE,"classid","e100:1","htb","rate",f"{rate}mbit","ceil",f"{rate}mbit"])
                for _name,minor,fraction,prio in SHARES:
                    run(["tc","class","add","dev",dev,"parent","e100:1","classid",f"e100:{minor}","htb","rate",f"{rate*fraction:.3f}mbit","ceil",f"{rate}mbit","prio",str(prio)])
                    run(["tc","qdisc","add","dev",dev,"parent",f"e100:{minor}","handle",f"{minor}:","fq_codel","limit","512","target","5ms","interval","100ms","memory_limit","1Mb"])
                    mark=minor<<16
                    run(["tc","filter","add","dev",dev,"parent",HANDLE,"protocol","ip","prio","10","handle",f"{mark}/0xff0000","fw","flowid",f"e100:{minor}"])
                # Preserve responsiveness of locally originated SSH on IPv4/IPv6.
                for priority,protocol in ((1,"ip"),(2,"ipv6")):
                    run(["tc","filter","add","dev",dev,"parent",HANDLE,"protocol",protocol,"prio",str(priority),"flower","ip_proto","tcp","src_port","22","classid","e100:10"])
            run(["nft","-f","-"],self.nft_base())
        except Exception:
            self.rollback(); raise

    def rerate(self,dev,rate):
        """Resize an already-owned hierarchy in place; shares and priorities hold."""
        if not self.state.exists(): raise RuntimeError("Policy not initialized")
        if dev not in (self.c["uplink"],self.c["downlink"]): raise ValueError("Unknown device")
        rate=float(rate)
        if not 1<=rate<=900: raise ValueError("Rate outside 1..900 Mbit/s")
        roots=[q for q in self.qdiscs(dev) if q.get("root")]
        if not roots or roots[0].get("handle")!=HANDLE:
            raise RuntimeError(f"{dev}: not our qdisc; refusing to re-rate")
        # class change keeps the fq_codel children and their backlogs intact.
        run(["tc","class","change","dev",dev,"parent",HANDLE,"classid","e100:1","htb","rate",f"{rate}mbit","ceil",f"{rate}mbit"])
        for _name,minor,fraction,prio in SHARES:
            run(["tc","class","change","dev",dev,"parent","e100:1","classid",f"e100:{minor}","htb","rate",f"{rate*fraction:.3f}mbit","ceil",f"{rate}mbit","prio",str(prio)])
        return rate

    def update(self,flows):
        if not self.state.exists(): raise RuntimeError("Policy not initialized")
        lines=[f"flush map inet {TABLE} flows"]
        entries=[]
        for f in flows:
            a,b,proto,sp,dp=f.key
            a=ipaddress.ip_address(a); b=ipaddress.ip_address(b)
            if a not in ipaddress.ip_network(self.c["lan"]) or proto not in (6,17) or not 0<=sp<=65535 or not 0<=dp<=65535:
                continue
            label=f.label if f.label in MARKS else 'best_effort'
            entries.append(f"{a} . {b} . {'tcp' if proto==6 else 'udp'} . {sp} . {dp} : jump class_{label}")
        if entries:
            lines.append(f"add element inet {TABLE} flows {{ "+", ".join(entries[:self.c["max_flows"]])+" }")
        # One atomic transaction: no partial map while packets traverse.
        run(["nft","-f","-"],"\n".join(lines)+"\n")

    def rollback(self):
        if not self.state.exists(): return
        state=json.loads(self.state.read_text()); errors=[]
        table=run(["nft","list","table","inet",TABLE],check=False)
        if table.returncode==0:
            if 'Tata EdgeQoS owned v1' not in table.stdout: raise RuntimeError("Foreign table: refusing deletion")
            run(["nft","delete","table","inet",TABLE])
        for dev,kind in state["baseline"].items():
            roots=[q for q in self.qdiscs(dev) if q.get("root")]
            if roots and roots[0].get("handle")==HANDLE:
                run(["tc","qdisc","del","dev",dev,"root","handle",HANDLE])
                current=[q for q in self.qdiscs(dev) if q.get("root")]
                if current and current[0]["kind"]!=kind and kind!="noqueue":
                    run(["tc","qdisc","replace","dev",dev,"root",kind])
            elif roots and roots[0].get("handle")!="0:": errors.append(dev)
        if errors: raise RuntimeError("Foreign qdisc found; investigate: "+",".join(errors))
        self.state.unlink()
