"""Identical bounded, header-only behavioral statistics for training and live use."""
import math
from dataclasses import dataclass

FEATURES_V2=['mean_bytes','std_bytes','packets_per_second','up_ratio','udp','duration',
             'mean_iat','std_iat','small_ratio','large_ratio','bytes_per_second','direction_switch_ratio']
BEHAVIORS=['gaming','streaming','interactive','bulk','realtime']
FEATURES_V3=FEATURES_V2+['remote_port']
QUEUE_FOR_BEHAVIOR={'gaming':'realtime','streaming':'best_effort','interactive':'interactive','bulk':'bulk','realtime':'realtime'}
WINDOW_SECONDS=10.0

@dataclass
class Window:
    start: float=0
    last: float=0
    n: int=0
    total: int=0
    sq: int=0
    up: int=0
    small: int=0
    large: int=0
    iats: float=0
    iat_sq: float=0
    switches: int=0
    direction: bool=False

    def add(self,size,upload,now):
        if self.n:
            dt=max(0,now-self.last); self.iats+=dt; self.iat_sq+=dt*dt
            self.switches+=int(upload!=self.direction)
        else: self.start=now
        self.last=now; self.n+=1; self.total+=size; self.sq+=size*size
        self.up+=size if upload else 0; self.small+=int(size<=200); self.large+=int(size>=1000)
        self.direction=upload

    def vector(self,udp):
        n=max(1,self.n); duration=max(.1,self.last-self.start); mean=self.total/n
        k=max(1,self.n-1); mi=self.iats/k
        return [mean,math.sqrt(max(0,self.sq/n-mean*mean)),self.n/duration,self.up/max(1,self.total),
                float(udp),duration,mi,math.sqrt(max(0,self.iat_sq/k-mi*mi)),self.small/n,self.large/n,
                self.total/duration,self.switches/k]
