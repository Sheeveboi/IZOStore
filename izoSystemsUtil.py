import threading;
import time;
import os;
import json;

rateLimitArr = {};
activeCooldowns = [];

def createTimeStamp(t) :
    s = 0;
    m = 0;
    h = 0;
    d = 0;
    
    for i in range(t):  
        s += 1;
        if (s >= 60) :
            m += 1;
            s = 0;
        if (m >= 60) :
            h += 1;
            m = 0;
        if (h >= 24) :
            h = 0;
            d += 1;
            
    return (s,m,h,d);

def checkRateLimit(d,conn,auth):
    f = open(os.path.join(d,"rateLimits.json"),"r");
    rateLimits = f.read();
    rateLimits = json.loads(rateLimits);
    f.close();
    
    rules = {} #will always emerge with a ruleset
    setDefault = False;
    
    rlList = rateLimits['rateLimits'];
    for RL in rlList:
        if (RL not in ["default","initSession"]) :
            f = open(os.path.join(d,RL+".auth"),"r");
            a = f.read();
            a = json.loads(a);
            f.close();
            if (auth in a) :
                rules = rlList[RL];
                setDefault = True;
                
    if (setDefault) :            rules = rlList['default'];
    if (auth == 'initSession') : rules = rlList['initSession'];
    
    suspensions = rateLimits['suspensions'];
        
        