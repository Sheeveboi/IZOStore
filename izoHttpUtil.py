import json;
def decodeHTTP(s):
    sp = s.replace('\r','');
    sp = sp.split('\n');
    
    method = sp[0].split(' ')[0];
    path = sp[0].split(' ')[1];
    body = sp[len(sp)-1];
    
    sp.remove(sp[0]);
    sp.remove(sp[len(sp)-1]);
    
    try : sp.remove('');
    except : pass;
    
    headers = {};
    for header in sp:
        pair = header.split(": ");
        headers[pair[0]] = pair[1];
        
    r = {
        'path' : path,
        'method' : method,
        'headers' : headers,
        'body' : body
    }
    return r;
    
def formatHTTP(status, headers = {}, body = '') :
    if (type(status) != str) : raise Exception(f"Expected type 'Str', got {type(status)}");
    http = f"HTTP/1.1 {status}\n"
    if (type(headers) != dict) : raise Exception(f"Expected type 'Dict', got {type(headers)}");
    for header in headers:
        http += f"{header}: {headers[header]}\n"
    if (type(body) != str) : raise Exception(f"Expected type 'Str', got {type(body)}");
    http += f"\n{body}";
    http = bytes(http,'utf-8');
    
    return http;
    
def sendError(conn,code,message) :
    postage = {'type' : 'error', 'code' : code, 'message' : message};
    conn.sendall(formatHTTP("200 OK",headers = {'Content-Type' : 'text/json'}, body = json.dumps(postage)));
    conn.close();
    
def sendJsonResponse(conn,d):
    postage = {'type' : 'reponse', 'd' : d};
    conn.sendall(formatHTTP("200 OK",headers = {'Content-Type' : 'text/json'}, body = json.dumps(postage)));
    conn.close();
    