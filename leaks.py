import argparse
import json
import requests
import hashlib

def file_read(path):
    with open(path, "r") as f:
        obj = f.readlines()
        for i in range(len(obj)):
            obj[i] = obj[i].rstrip()
        return obj

def check_leak(password):
    
    
    cut_hash = hashlib.sha1(password.encode()).hexdigest()[:5].upper()
    hashed_password = hashlib.sha1(password.encode()).hexdigest()[5:].upper()
    resp = requests.request("GET","https://api.pwnedpasswords.com/range/"+ cut_hash)
    
    hashes = resp.content.decode().split('\r\n')
    # print(hashes)
    for h in hashes:
        leak_hash = h.split(":")[0]
        
        if hashed_password in leak_hash:
            return "LEAKED" 
    return "NOT LEAKED"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="passleak", description="Detecting password leaks")
    parser.add_argument("-p","--password" , help="Target password for checking leaks")
    parser.add_argument("-f","--file", help="Path to file including passwords list")
    args = parser.parse_args()
    if args.password:
        try:
            password= str(args.password)
            print(password+": "+check_leak(password))
            
            
        except Exception as e:
            raise e
        
    
    if args.file:
        try:
            passwords = file_read(args.file)
            for password in passwords:
                print(password+": "+check_leak(password))
        except Exception as e:
            raise e

    
