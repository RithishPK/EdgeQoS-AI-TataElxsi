"""Read-only topology and connectivity diagnostics. Never prints Wi-Fi secrets."""
import ipaddress
import json
import platform
from pathlib import Path
from .policy import run


def inspect(c):
    commands={
        "addresses":["ip","-j","address"], "routes":["ip","-j","route"],
        "devices":["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device","status"],
        "shared_method":["nmcli","-g","ipv4.method","connection","show",c["hotspot_connection"]],
        "forwarding":["sysctl","-n","net.ipv4.ip_forward"],
        "nft":["nft","-j","list","ruleset"], "sockets":["ss","-ulpn"],
        "neighbors":["ip","-j","neigh","show","dev",c["downlink"]],
        "qdisc":["tc","-j","qdisc","show"],
        "uplink_probe":["curl","--silent","--show-error","--max-time","8","-I","https://www.debian.org"],
    }
    result={"platform":platform.platform(),"read_only":True,"checks":{},"failures":[],"warnings":[]}
    for name,args in commands.items():
        try:
            p=run(args,check=False)
            out=p.stdout.strip()
            if name in ("addresses","routes","nft","neighbors","qdisc") and p.returncode==0: out=json.loads(out)
            result["checks"][name]={"returncode":p.returncode,"data":out,"error":p.stderr.strip()}
        except Exception as e:
            result["checks"][name]={"returncode":-1,"error":str(e)}
    checks=result["checks"]
    for name in ("addresses","routes","devices","shared_method","forwarding","nft","sockets","qdisc"):
        if checks[name]["returncode"]: result["failures"].append(name+" unavailable")
    if checks["shared_method"].get("data")!="shared": result["failures"].append("Hotspot is not ipv4.method=shared")
    if checks["forwarding"].get("data")!="1": result["failures"].append("IPv4 forwarding disabled")
    addrs=checks["addresses"].get("data",[])
    nets={}; local=set()
    for iface in addrs if isinstance(addrs,list) else []:
        nets[iface["ifname"]]=[]
        for a in iface.get("addr_info",[]):
            local.add(a["local"])
            if a["family"]=="inet": nets[iface["ifname"]].append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}",strict=False))
    expected=ipaddress.ip_network(c["lan"])
    if expected not in nets.get(c["downlink"],[]) or c["gateway"] not in local:
        result["failures"].append("Configured LAN/gateway differs from live downlink")
    for a in nets.get(c["uplink"],[]):
        if a.overlaps(expected): result["failures"].append("LAN and uplink subnets overlap: same-subnet bypass risk")
    routes=checks["routes"].get("data",[])
    if not any(r.get("dst")=="default" and r.get("dev")==c["uplink"] for r in routes if isinstance(r,dict)):
        result["failures"].append("Default route is not via configured uplink")
    nft=checks["nft"].get("data",{})
    if "flowtable" in json.dumps(nft): result["failures"].append("Flow offload detected: forwarding hook may be bypassed")
    if "masquerade" not in json.dumps(nft): result["warnings"].append("No masquerade rule detected; inspect NAT")
    if ":67" not in str(checks["sockets"].get("data","")): result["warnings"].append("No DHCP port visible")
    if checks['uplink_probe']['returncode']: result['warnings'].append('Pi HTTPS uplink probe failed; client internet remains unverified')
    lease=Path(f"/var/lib/NetworkManager/dnsmasq-{c['downlink']}.leases")
    result["dhcp_leases"]=lease.read_text().splitlines() if lease.exists() else []
    result["warnings"] += ["Same-subnet peers can switch/ARP directly: routed QoS does not cover them.",
        "Pi outbound HTTP success is not proof of phone DHCP/DNS/NAT/internet success.",
        "IPv6 and unsupported/fragmented traffic use default queue; IPv4 AI marking only."]
    result["ready_for_monitor"]=not result["failures"]
    return result
