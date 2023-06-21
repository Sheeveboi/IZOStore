from izoStore import izoHttpUtil;
from argon2 import PasswordHasher;
import os;
import json;
import random;
import math;
import shutil;

ph = PasswordHasher();

def checkModelData(data,obj) :

    #-- standard blocks of data --
    for detect in ['create','read','write','dataRules','data']: #key missing
        if (detect not in data) : 
            raise ValueError(f"Error in model file '{obj}'. '{detect}' key not found"); 
            
    #-- create --
    for detect in ['loginIdentifier','collectionName','childCollections','keypaths']:
        if (detect not in data['create']) :
            raise ValueError(f"Error in model file '{obj}' in dict 'create'. '{detect}' key not found."); 
    
    #-- type enforcment --
    
    #create
    if (type(data['create']) != dict) : raise TypeError(f"Error in model file '{obj}' for value 'create. Expected 'Dict', got '{type(data['create'])}'.");  
    
    #collectionName
    if (type(data['create']['collectionName']) != str): raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'collectionName'. Expected 'Str', got '{type(data['create']['keyGen'])}'."); 
    
    #childCollections
    if (type(data['create']['childCollections']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'childCollections'. Expected 'List', got '{type(data['create']['childCollections'])}'."); 
    if (any(type(x) != str for x in data['create']['childCollections']) and len(data['create']['childCollections']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'childCollections'. List should contain only type 'Str' if length not '0'."); 
    
    #filepaths
    if (type(data['create']['keypaths']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'keypaths'. Expected 'List', got '{type(data['create']['keypaths'])}'."); 
    if (any(type(x) != str for x in data['create']['keypaths']) and len(data['create']['keypaths']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'keypaths'. List should contain only type 'Str' if length not '0'.");    
    
    #loginIdentifier
    if (type(data['create']['loginIdentifier']) != bool) : raise TypeError(f"Error in model file '{obj}' in dict 'create' for value 'loginIdentifier'. Expected Bool, got '{type(data['create']['loginIdentifier'])}'.");
    
    #-- read --
    for detect in ['mode','filepaths'] :
        if (detect not in data['read']) :
            raise ValueError(f"Error in model file '{obj}' in dict 'read'. '{detect}' key not found."); 
    
    #-- type enforcment --
    #read
    if (type(data['read']) != dict) : raise TypeError(f"Error in model file '{obj}' for value 'read'. Expected 'Dict', got '{type(data['read'])}'.");
    
    #mode
    if (type(data['read']['mode']) != int) : raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'mode'. Expected 'Int', got '{type(data['read']['mode'])}'.");
    if (data['read']['mode'] not in [0,1,2,3]) : raise ValueError(f"Error in model file '{obj}' in dict 'read' for value 'mode'. Value outside of acceptable range (Should be either 0, 1, 2, or 3)'.");
    
    #filepaths
    if (type(data['read']['filepaths']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'filepaths'. Expected 'List', got '{type(data['read']['filepaths'])}'."); 
    if (any(type(x) != str for x in data['read']['filepaths']) and len(data['read']['filepaths']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'filepaths'. List should contain only type 'Str' if length not '0'.");


    #-- write --
    for detect in ['mode','filepaths'] :
        if (detect not in data['write']) :
            raise ValueError(f"Error in model file '{obj}' in dict 'write'. '{detect}' key not found."); 
    
    #-- type enforcment --
    #write
    if (type(data['write']) != dict) : raise TypeError(f"Error in model file '{obj}' for value 'write'. Expected 'Dict', got '{type(data['write'])}'.");
    
    #mode
    if (type(data['write']['mode']) != int) : raise TypeError(f"Error in model file '{obj}' in dict 'write' for value 'mode'. Expected 'Int', got '{type(data['write']['mode'])}'.");
    if (data['write']['mode'] not in [0,1,2,3]) : raise ValueError(f"Error in model file '{obj}' in dict 'write' for value 'mode'. Value outside of acceptable range (Should be either 0, 1, 2, or 3)'.");
    
    #filepaths
    if (type(data['write']['filepaths']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'write' for value 'filepaths'. Expected 'List', got '{type(data['write']['filepaths'])}'."); 
    if (any(type(x) != str for x in data['write']['filepaths']) and len(data['write']['filepaths']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'filepaths'. List should contain only type 'Str' if length not '0'.");
    
    #-- data rules --
    
    if (type(data['dataRules']) not in [dict,bool]) : raise TypeError(f"Error in model file '{obj}' for value 'dataRules'. Expected 'Dict' or False (Bool), got '{type(data['dataRules'])}'.");
    if (type(data['dataRules']) == bool and type(data['dataRules']) == True) : raise TypeError(f"Error in model file '{obj}' for value 'dataRules'. Bool bypass set to True instead of False.");
    
    #-- find read write rules and check them --
    def recurseTree(d,obj):
        for key in d:
            if (key in ['read','write']) :
                if (type(d[key]) != dict) : raise TypeError(f"Error in model file '{obj}' in dict 'dataRules' for value '{key}'. Expected 'Dict', got '{type(d[key])}'.");
                else : #if a ruleset is found within a data key
                    
                    if (key == 'read') :
                        #read
                        for detect in ['mode','filepaths'] :
                            if (detect not in d['read']) : raise ValueError(f"Error in model file '{obj}' in dict 'read'. '{detect}' key not found.");
                        #mode
                        if (type(d['read']['mode']) != int) : raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'mode'. Expected 'Int', got '{type(d['read']['mode'])}'.");
                        if (d['read']['mode'] not in [0,1,2,3]) : raise ValueError(f"Error in model file '{obj}' in dict 'read' for value 'mode'. Value outside of acceptable range (Should be either 0, 1, 2, or 3)'.");
                        
                        #filepaths
                        if (type(d['read']['filepaths']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'filepaths'. Expected 'List', got '{type(d['read']['filepaths'])}'."); 
                        if (any(type(x) != str for x in d['read']['filepaths']) and len(d['read']['filepaths']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'read' for value 'filepaths'. List should contain only type 'Str' if length not '0'.");
                    
                    elif (key == 'write') :
                        #write
                        for detect in ['mode','filepaths'] :
                            if (detect not in d['write']) : raise ValueError(f"Error in model file '{obj}' in dict 'write'. '{detect}' key not found.");
                        #mode
                        if (type(d['write']['mode']) != int) : raise TypeError(f"Error in model file '{obj}' in dict 'write' for value 'mode'. Expected 'Int', got '{type(d['write']['mode'])}'.");
                        if (d['write']['mode'] not in [0,1,2,3]) : raise ValueError(f"Error in model file '{obj}' in dict 'write' for value 'mode'. Value outside of acceptable range (Should be either 0, 1, 2, or 3)'.");
                        
                        #filepaths
                        if (type(d['write']['filepaths']) != list): raise TypeError(f"Error in model file '{obj}' in dict 'write' for value 'filepaths'. Expected 'List', got '{type(d['write']['filepaths'])}'."); 
                        if (any(type(x) != str for x in d['write']['filepaths']) and len(d['write']['filepaths']) > 0) : raise TypeError(f"Error in model file '{obj}' in dict 'write' for value 'filepaths'. List should contain only type 'Str' if length not '0'.");
                        
            elif (type(d[key]) == dict) : #if a nested dict is found    
                recurseTree(d[key],obj); #search that dict to see if its a ruleset
                
    if (type(data['dataRules']) != bool) : recurseTree(data['dataRules'],obj);
    
    #-- data --
    
    if (type(data['data']) != dict) : raise TypeError(f"Error in model file '{obj}' in dict 'data'. Expected 'Dict', got {type(data['data'])}."); 
 
def checkAuth(rw,d,p,model,auth) :
    mode = model[rw]['mode']
    if (mode == 0) : 
        return True; #just do it lol
    elif (mode == 1) :
        #check root parent write rules. check root parent. if no root parent found, pass
        levels = p.split("/");
        current = d;
        for level in levels :
            current = os.path.join(current,level);
            if ("data.json" in os.listdir(current)) :
                f = open(os.path.join(current,"data.json"),"r");
                data = f.read();
                data = json.loads(data);
                f.close();
                
                model = data['meta']['derivedFrom'];
                f = open(os.path.join(d,model + ".mdl"),"r");
                model = f.read();
                model = json.loads(model);
                f.close();
                
                if (model[rw]['mode'] == 1) :
                    if (data['meta']['associatedKey'] == auth) : return True;
                    else : return False;
                else : return checkAuth(rw,d,current.replace(d + "/",""),model,auth);
                    
                
        return True;
    elif (mode == 2) :
        for authFile in model[rw]['filepaths'] :
            try : 
                f = open(os.path.join(d,authFile + ".auth"),"r");
                keys = f.read();
                keys = json.loads(keys);
                f.close();
                
                if (auth in keys) : return True;
            except : raise Warning(f"filepath/filename {authFile} does not point to a .auth file");
        return False;
    elif (mode == 3) :
        #first check for keys within filepaths, then check root parent write rules. if no root parent found, pass
        for authFile in model[rw]['filepaths'] :
            try : 
                f = open(os.path.join(d,authFile + ".auth"),"r");
                keys = f.read();
                keys = json.loads(keys);
                f.close();
                
                if (auth in keys) : return True;
            except : raise Warning(f"filepath/filename {authFile} does not point to a .auth file");
        
        levels = p.split("/");
        current = d;
        for level in levels :
            current = os.path.join(current,level);
            if ("data.json" in os.listdir(current)) :
            
                f = open(os.path.join(current,"data.json"),"r");
                data = f.read();
                data = json.loads(data);
                f.close();
                
                model = data['meta']['derivedFrom'];
                f = open(os.path.join(d,model + ".mdl"),"r");
                model = f.read();
                model = json.loads(model);
                f.close();
                
                if (model[rw]['mode'] == 3) :
                    if (data['meta']['associatedKey'] == auth) : return True;
                    else : return False;
                else : return checkAuth(rw,d,current.replace(d + "/",""),model,auth);
                    
                
        return True;
    return False;
 
def checkKeyAuth(rw,d,p,keyRules,auth) :
    keys = [];
    if (keyRules != False) :
        def recurseTree(di,parentName,secondParent) :
            for key in di:
                if (key in ['read','write']) :
                    
                    if (key == rw) : 
                        t = checkAuth(rw,d,p,di,auth);
                        print(t);
                        if (not t) :
                            keys.append([secondParent, parentName]);
                            
                    
                elif (type(di[key]) == dict) :    
                    recurseTree(di[key],parentName,key);
        recurseTree(keyRules,"None","None");
    return keys;
 
def generateAuthKey() :
    a = "abcdefghijklmnopqrstuvwxyz";
    n = "1234567890";
    oup = "";
    for i in range(0,50) :
        if (random.random() > .5) :
            if (random.random() > .5) : oup += a[math.floor(random.random() * len(a))];
            else                      : oup += a[math.floor(random.random() * len(a))].upper();
        else                          : oup += n[math.floor(random.random() * len(n))];
    return oup;
    
def initSession(d,p,conn,password) :

    endpoint = os.path.join(d,p);
    
    if ("data.json" not in os.listdir(endpoint)) : 
        izoHttpUtil.sendError(conn,405,"Not Allowed. Path does not point to object");
        return None;
        
    f = open(os.path.join(endpoint,"data.json"),"r");
    objData = f.read();
    objData = json.loads(objData);
    f.close();
    
    go = False
    try :
        ph.verify(objData['meta']['loginIdentifier'],password);
        go = True;
    except : pass;
    if (go or objData['meta']['loginIdentifier'] == False) :
    
        f = open(os.path.join(d,objData['meta']['derivedFrom'] + ".mdl"),"r");
        model = f.read();
        model = json.loads(model);
        
        key = generateAuthKey();
        
        for authPath in model['create']['keypaths']:
            try :
                f = open(os.path.join(d,authPath + ".auth"),"r");
                k = f.read();
                k = json.loads(k);
                f.close();
                
                if (objData['meta']['associatedKey'] in k) : k.remove(objData['meta']['associatedKey']);
                k.append(key);
                
                f = open(os.path.join(d,authPath + ".auth"),"w");
                f.write(json.dumps(k));
                f.close();
                
            except : pass;
        objData['meta']['associatedKey'] = key;
        
        f = open(os.path.join(endpoint,"data.json"),"w");
        f.write(json.dumps(objData));
        f.close();
        
        p = { 'auth' : objData['meta']['associatedKey'] }
        izoHttpUtil.sendJsonResponse(conn,p);
    else : 
        izoHttpUtil.sendError(conn,401,"Unauthorized");
        return None;
        
def endSession(d,p,conn,password) :

    endpoint = os.path.join(d,p);
    
    if ("data.json" not in os.listdir(endpoint)) : 
        izoHttpUtil.sendError(conn,405,"Not Allowed. Path does not point to object");
        return None;
        
    f = open(os.path.join(endpoint,"data.json"),"r");
    objData = f.read();
    objData = json.loads(objData);
    f.close();
    
    go = False
    try :
        ph.verify(objData['meta']['loginIdentifier'],password);
        go = True;
    except : pass;
    if (go or objData['meta']['loginIdentifier'] == False) :
    
        f = open(os.path.join(d,objData['meta']['derivedFrom'] + ".mdl"),"r");
        model = f.read();
        model = json.loads(model);
        
        for authPath in model['create']['keypaths']:
            try :
                f = open(os.path.join(d,authPath + ".auth"),"r");
                k = f.read();
                k = json.loads(k);
                f.close();
                
                if (objData['meta']['associatedKey'] in k) : k.remove(objData['meta']['associatedKey']);
                
                f = open(os.path.join(d,authPath + ".auth"),"w");
                f.write(json.dumps(k));
                f.close();
                
            except : pass;
        objData['meta']['associatedKey'] = None;
        
        f = open(os.path.join(endpoint,"data.json"),"w");
        f.write(json.dumps(objData));
        f.close();
        
        izoHttpUtil.sendJsonResponse(conn,{});
    else : 
        izoHttpUtil.sendError(conn,401,"Unauthorized");
        return None;
        
def get(d,p,conn,auth) :

    endpoint = os.path.join(d,p);
    
    objData = {};
    
    def r(endpoint) :
        addition = {};
        for collection in os.listdir(endpoint) :
            if ("." not in collection) :
                addition[collection] = {};
                newEndpoint = os.path.join(endpoint,collection);
                for obj in os.listdir(newEndpoint) :
                    if ("data.json" in os.listdir(os.path.join(newEndpoint,obj))) : 
                        
                        f = open(os.path.join(os.path.join(newEndpoint,obj),"data.json"),"r");
                        postage = f.read();
                        postage = json.loads(postage);
                        f.close();
                    
                        f = open(os.path.join(d,postage['meta']['derivedFrom'] + ".mdl"),"r");
                        model = f.read();
                        model = json.loads(model);
                        
                        if (not checkAuth("read",d,p,model,auth)) : 
                            izoHttpUtil.sendError(conn,401,"Unauthorized");
                            return None;
                        
                        offLimitsKeys = checkKeyAuth("write",d,p,model['dataRules'],auth);
                        
                        def recurseData(dat,parent) :
                            for key in dat:
                                if (not any(x[0] == parent and x[1] == key for x in offLimitsKeys)) :
                                    if (type(dat[key]) == dict) : dat[key] = recurseData(dat[key],key);
                                    if (dat[key] == None) : return None;
                                else : dat.pop(key);
                            return dat;
                                    
                        addition[collection][obj] = recurseData(postage['data'],"None");
                        
                        for o in os.listdir(os.path.join(newEndpoint,obj)) :
                            if ("." not in o) :
                                addition[o] = r(os.path.join(newEndpoint,obj));
        return addition;

    if ("data.json" in os.listdir(endpoint)) : 
        
        f = open(os.path.join(endpoint,"data.json"),"r");
        objData = f.read();
        objData = json.loads(objData);
        f.close();
    
        f = open(os.path.join(d,objData['meta']['derivedFrom'] + ".mdl"),"r");
        model = f.read();
        model = json.loads(model);
        
        if (not checkAuth("read",d,p,model,auth)) : 
            izoHttpUtil.sendError(conn,401,"Unauthorized");
            return None;
        
        offLimitsKeys = checkKeyAuth("read",d,p,model['dataRules'],auth);
        print(offLimitsKeys);
        
        def recurseData(dat,parent) :
            oup = dat.copy();
            for key in dat:
                if (not any(x[1] == parent and x[0] == key for x in offLimitsKeys)) :
                    if (type(dat[key]) == dict) : oup[key] = recurseData(dat[key],key);
                    if (dat[key] == None) : return None;
                else : oup.pop(key);
            return oup;
                    
        objData = recurseData(objData['data'],"None");
        
        add = r(endpoint);
        for k in add : objData[k] = add[k];
    else : 
        izoHttpUtil.sendError(conn,405,"Not Allowed. Path does not point to object");
        return None;
     
    izoHttpUtil.sendJsonResponse(conn,objData);
        
def post(d,p,conn,data) :
    endpoint = os.path.join(d,p);
    if ("data.json" in os.listdir(endpoint)) : 
        izoHttpUtil.sendError(conn,405,"Not Allowed");
        return None;
    for key in ['obj','name','auth','data'] :
        if (key not in data) : 
            izoHttpUtil.sendError(conn,406,f"'{key}' not in body");
            return None;
    f = None;
    try : f = open(os.path.join(d,data['obj'] + ".mdl"),"r");
    except : 
        izoHttpUtil.sendError(conn,404,"Object name does not reference an existing model");
        return None;
    model = f.read();
    model = json.loads(model);
    targetCollection = p.split("/")[len(p.split("/")) - 1];
    if (model['create']['collectionName'] != targetCollection) :
        izoHttpUtil.sendError(conn,405,"Not Allowed");
        f.close();
        return None;
    f.close();
    
    overwrite = False;
    overwriteAuth = True;
    newObject = os.path.join(endpoint,data['name']);
    try : 
        os.chdir(newObject);
        overwrite = True;
    except : pass;
    if (overwrite) :
        overwriteAuth = checkAuth('write', d, os.path.join(p,data['name']), model, data['auth']);
        print(overwriteAuth);
    print(f"overwrite: {overwrite}");
    
    if (checkAuth('write',d,p,model,data['auth']) and overwriteAuth) : #if overwriting an object, refer to the objects authorization. if not, refer to the models create rules
        
        oldKey = None;
        if (overwrite) :
            dat = open(os.path.join(os.path.join(d,p + "/" + data['name']),"data.json"),"r");
            dat = dat.read();
            oldKey = json.loads(dat)['meta']['associatedKey'];
            
        postage = {
            "meta" : { 
                "associatedKey" : oldKey,
                "derivedFrom" : data['obj'],
                "loginIdentifier" : False
            },
            "data" : model['data']
        }
        if (model['create']['loginIdentifier']) : 
            if ('password' not in data) :
                izoHttpUtil.sendError(conn,406,f"'password' not in body");
                return None;
            postage['meta']['loginIdentifier'] = ph.hash(data['password']);
            
        offLimitsKeys = checkKeyAuth("write",d,p,model['dataRules'],data['auth']);
        def recurseData(dat,req,parent) :
            for key in dat:
                if (key in req and any(x[1] == parent and x[0] == key for x in offLimitsKeys)) :
                    if (type(req[key]) == dict and type(dat[key]) == dict) : dat[key] = recurseData(dat[key],req[key],key);
                    elif (type(req[key]) == type(dat[key]))                : dat[key] = req[key];
                    else :
                        izoHttpUtil.sendError(conn,406,f"'{key}' key in 'data' does not match type in the model. Expected '{type(dat[key])}'");
                        return None;
                    if (dat[key] == None) : return None;
            return dat;
        postage['data'] = recurseData(postage['data'],data['data'],"None");
        if (postage['data'] == None) : return None; 
                    
        if (overwrite) : shutil.rmtree(newObject);
        os.mkdir(newObject);
        for newD in model['create']['childCollections'] :
            os.mkdir(os.path.join(newObject,newD));
            
        f = open(os.path.join(newObject,"watchkeys.auth"),"w") 
        f.write(json.dumps([]));
        f.close();
        
        f = open(os.path.join(newObject,"data.json"),"w");
        f.write(json.dumps(postage));
        f.close();
        
        izoHttpUtil.sendJsonResponse(conn,postage);
    else : 
        izoHttpUtil.sendError(conn,401,"Unauthorized");
        return None;        
        
