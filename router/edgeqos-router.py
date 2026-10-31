#!/usr/bin/python3
"""Reconcile hotspot and selected uplink. Never flush firewall or reset profiles."""
import json, subprocess, pathlib, os, fcntl

def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, timeout=35, check=check)

def reconcile():
    run('nmcli','radio','wifi','on')
    active=run('nmcli','-g','GENERAL.CONNECTION','device','show','wlan0',check=False)
    if active.returncode==0 and active.stdout.strip()!='Tata-AI-Router':
        run('nmcli','--wait','15','connection','up','Tata-AI-Router',check=False)
    if pathlib.Path('/sys/class/net/usb0').exists():
        state=run('nmcli','-g','GENERAL.STATE','device','show','usb0',check=False).stdout
        if not state.startswith('100'):
            run('nmcli','--wait','15','connection','up','EDGEqos-USB',check=False)
    routes=json.loads(run('ip','-j','-4','route','show','default').stdout)
    eligible=[r for r in routes if r.get('dev') in ('usb0','eth0') and 'linkdown' not in r.get('flags',[])]
    if not eligible:
        return # hotspot stays available even without internet
    selected=min(eligible,key=lambda r:r.get('metric',0))['dev']
    p=pathlib.Path('/etc/edgeqos/config.json'); c=json.loads(p.read_text())
    if c['uplink']!=selected:
        # Stop with OLD config so owned QoS is removed from the old interface.
        run('systemctl','stop','edgeqos')
        c['uplink']=selected; c['mode']='monitor'
        tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(c,indent=2)+'\n');os.chmod(tmp,0o644);tmp.replace(p)
        run('systemctl','start','edgeqos')
        print('EDGEqos uplink:',selected,'; normal routing after switch',flush=True)
    elif run('systemctl','is-active','edgeqos',check=False).returncode:
        run('systemctl','start','edgeqos')

if __name__=='__main__':
    with open('/run/edgeqos-router.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        reconcile()
