import asyncio;
import socket;
import os;
import json;
from izoStore import izoHttpUtil;
from izoStore import izoFileUtil;
from izoStore import izoSystemsUtil;
  
class Database:

    def __init__(this,host,directory):
        
        this.host = host;
        this.directory = directory;
    
    def run(this):
        
        os.chdir(this.directory);
        
        if ("rateLimits.json" not in os.listdir()): 
            f = open(os.path.join(this.directory,"rateLimits.json"),"w");  
            
            #'default' is the default ruleset to follow if a session key is not found within any auth files mentioned within "rateLimits"
            #'initSession' is an optional but still a reserved ruleset name that can be added for useage in limiting session creation
            
            p = {
                "rateLimits" : {
                    "default" : {
                        "cooldown" : 1,
                        "removeStrikesCooldown" : 5,
                        "strikesUntilMute" : 20,
                        "muteLength" : 60*60,
                        "mutesUntilBan" : 5
                    }   
                },
                "suspensions" : {}
            }
            
            f.write(json.dumps(p));
            f.close();
        
        foundMD = False;
        foundAuth = False;
        foundCollections = False;
        for obj in os.listdir():
            if (obj == "default.auth") : raise Exception("Illegal name for auth file. Cannot be named 'default.auth'.");
            if (obj == "initSession.auth") : raise Exception("Illegal name for auth file. Cannot be named 'initSession.auth'.");
            if   ("." not in obj) : 
                foundCollections = True;
            elif (obj[len(obj) - 5:] == ".auth") : 
            
                f = open(os.path.join(this.directory,obj),"r");
                data = f.read();
                data = json.loads(data);
                if (type(data) != list) : raise TypeError(f"Expected file '{obj}' to contain List. Got {type(data)} instead.");
                foundAuth = True;
                
            elif (obj[len(obj) - 4:] == ".mdl") : 

                f = open(os.path.join(this.directory,obj),"r");
                data = f.read();
                data = json.loads(data);
                if (type(data) != dict) : raise TypeError(f"Expected file '{obj}' to contain Dict. Got {type(data)} instead.");
                
                izoFileUtil.checkModelData(data,obj);
                foundMD = True;
                
        if (not foundMD)          : raise Exception("No .mdl files found within given directory");
        if (not foundAuth)        : raise Exception("No .auth files found within given directory");
        if (not foundCollections) : raise Exception("No collection folders found within given directory");
    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((this.host, 80));
            s.listen();
            print(f"database active at host '{this.host}'");
            while True:
                conn, addr = s.accept();
                
                data = conn.recv(1048576);
                data = bytes.decode(data, "utf-8");
                data = izoHttpUtil.decodeHTTP(data);
                
                path = data['path'][1:];
                method = data['method'];
                headers = data['headers'];
                body = None;
                go = False;
                try : 
                    body = json.loads(data['body']);
                    go = True
                except : 
                    izoHttpUtil.sendError(conn,406,"Request body not json/contains invalid json");
                
                print(f"Path: {path} \nMethod: {method}\n---");
                
                if (go) :
                    if (len(path) > 1) :
                        endpoint = os.path.join(this.directory,path);
                        go = False;
                        try : 
                            os.chdir(endpoint);
                            go = True;
                        except : izoHttpUtil.sendError(conn,404,"Endpoint does not exist");
                        if (go):
                            if   (method == "GET")  : 
                                if   ('method' in headers):
                                    if ('pass' in headers) :
                                        if   (headers['method'] == 'LOGIN')  : izoFileUtil.initSession(this.directory,path,conn,headers['pass']);
                                        elif (headers['method'] == 'LOGOUT') : izoFileUtil.endSession(this.directory,path,conn,headers['pass']);
                                        elif (headers['method'] == 'WATCH')  : 
                                    else : izoHttpUtil.sendError(conn,406,"Invalid headers");
                                else : izoFileUtil.get(this.directory,path,conn,body);
                            elif (method == "POST")   : izoFileUtil.post(this.directory,path,conn,body);
                            elif (method == "PATCH")  :  
                                if ('key' in headers and 'value' in headers) : izoFileUtil.patch(this.directory,path,conn,body,headers['key'],headers['value']);
                                else : izoHttpUtil.sendError(conn,406,"Invalid headers");
                            elif (method == "DELETE") : izoFileUtil.delete(this.directory,path,conn,body);
                            else :
                                conn.sendall(izoHttpUtil.formatHTTP("200 OK",headers = {'Content-Type' : 'text/html'}, body = "this is just a test response"));
                                conn.close();
                        
                    else : izoHttpUtil.sendError(conn,405,"Not Allowed");