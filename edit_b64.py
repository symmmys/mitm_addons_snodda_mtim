"""base64 decode everything in the request, then encode it back when done editing"""
"""work in progress"""

import pyperclip
import re
from base64 import b64encode, b64decode
import logging
import subprocess
from collections.abc import Sequence
from typing import BinaryIO
from urllib.parse import quote

from mitmproxy import io
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import types
from mitmproxy.log import ALERT
from mitmproxy.net.http.http1 import assemble
from mitmproxy import exceptions
from mitmproxy import master
from mitmproxy import ctx
from mitmproxy.tools.console import window
from mitmproxy.tools.console.consoleaddons import ConsoleAddon
from mitmproxy.tools.console.grideditor.editors import HeaderEditor

LOGGER = logging.getLogger(__name__)
KEYWORD_REGEX = re.compile(b'(.*=)*([-A-Za-z0-9+/%]*={0,3}$)')
HEADER_REGEX = re.compile(b'(HEADER_.*:::)(.*:::)(.*)')
QUERY_REGEX = re.compile(b'(QUERY_.*:::)(.*:::)(.*)')

def padded_decode(bytes_in):
    bytes_in = bytes_in.rstrip(b'=')
    bytes_in = bytes_in.rstrip(b'%3d')
    bytes_in = bytes_in.rstrip(b'%3D')
    logging.info(f"bytes_in: {bytes_in}")
    padding = ( (0 - len(bytes_in)) % 4 )
    logging.info(f"padding: {padding}")
    bytes_in = bytes_in + (b"=" * padding)
    logging.info(f"bytes_in with padding: {bytes_in}")
    if len(bytes_in) % 4 == 0:
        try:
            bytes_out = b64decode(bytes_in)
        except Exception as e:
            try:
                logging.info(f"Error b64decoding: {e}")
                logging.info("trying urlsafe_b64decode...")
                bytes_out = urlsafe_b64decode(bytes_in)
            except Exception as f:
                logging.info(f"Could not decode: {f}")
                raise ValueError(f"'{bytes_in}' could not be decoded as either base64 or urlsafe_base64")
                return bytes_in
    logging.info(f"bytes_out: {bytes_out}")
    return bytes_out

def url_base64_encode(bytes_in):
    return b64encode(bytes_in)

def urlquote_encode(bytes_in):
    return quote(b64encode(bytes_in)).encode()

class Base64Editor(HeaderEditor):

    def __init__(self,master):
        super().__init__(master)
        self.original_b64_headers = dict()

    title = "Base64 decode headers and queries found in request, edit them, and reincode."


    def get_data(self, flow):
        dummy_data = []
        match_index = 0
        for header_tuple in flow.request.headers.fields:
            match = KEYWORD_REGEX.match(header_tuple[1])
            if match and len(match.groups()) > 1:
                try:
                    logging.info(f"base64 match.groups() : {match.groups()}")
                    if match.groups()[0] is not None:
                        this_header_name = f"HEADER_{match_index}:::{header_tuple[0]}:::".encode()+match.groups()[0]
                    else:
                        this_header_name = f"HEADER_{match_index}:::{header_tuple[0]}:::".encode()
                    this_header_val = padded_decode(match.groups()[1])
                    dummy_data.append((this_header_name,this_header_val))
                    match_index = match_index + 1
                    if header_tuple not in self.original_b64_headers:
                        self.original_b64_headers[header_tuple] = this_header_name
                except ValueError as v:
                    continue
        match_index = 0
        for query_tuple in flow.request.query.fields:
            match = KEYWORD_REGEX.match(query_tuple[1].encode())
            if match:
                try:
                    logging.info(f"query_tuple: {query_tuple}")
                    if match.groups()[0] is not None:
                        this_query_name = f"QUERY_{match_index}:::{query_tuple[0]}:::{match.groups()[0]}".encode()
                    else:
                        this_query_name = f"QUERY_{match_index}:::{query_tuple[0]}:::".encode()
                    this_query_val = padded_decode(query_tuple[1].encode())
                    match_index = match_index + 1
                except ValueError as V:
                    continue
        return dummy_data

    def set_data(self, vals, flow):
        http_match_index = 0
        http_match_dict = dict()
        query_match_dict = dict()
        for component_tuple in vals:
            header_match = HEADER_REGEX.match(component_tuple[0])
            query_match = QUERY_REGEX.match(component_tuple[0])
            if header_match and len(header_match.groups()) >1:
                suffix = header_match.groups()[2]
                if suffix is not None:
                    http_match_dict[component_tuple[0]] = suffix + urlquote_encode(component_tuple[1])
                else:
                    http_match_dict[component_tuple[0]] = urlquote_encode(component_tuple[1])
            if QUERY_REGEX.match(component_tuple[0]) and len(header_match.groups()) > 1:
                suffix = query_match.groups()[2]
                if suffix is not None:
                    query_match_dict[component_tuple[0]] = suffix + urlquote_encode(component_tuple[1])
                else:
                    query_match_dict[component_tuple[0]] = urlquote_encode(component_tuple[1])
        new_fields_builder = []
        for req_header in flow.request.headers.fields:
            if req_header in self.original_b64_headers:
                new_fields_builder.append((req_header[0],http_match_dict[self.original_b64_headers[req_header]]))
            else:
                new_fields_builder.append(req_header)
        flow.request.headers.fields = tuple(new_fields_builder)
        query_update_dict = dict()
        for key in query_match_dict:
            query_update_dict[key.decode('utf-8')] = query_match_dict[key].decode('utf-8')
        for item in query_update_dict:
            logging.info(f"query_match_dict:{query_match_dict}")
            flow.request.query.update({item:query_update_dict[item]})

class EditBase64(ConsoleAddon):
    @command.command("edit_b64")
    def edit_b64(
        self,
        flows: Sequence[flow.Flow]
    ) -> None:
        if len(flows) > 1:
            logging.log(ALERT, "Please specify a single flow, e.g. using `@focus`. Annoying, I know. Command not run.")
            return
        logging.debug("[edit_b64s.py] log level is set to debug or higher.")
        flowdex = 0
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                main_window = self.master.window
                jeditor = Base64Editor(self.master)
                main_window.stacks[0].windows["jeditor"] = jeditor
                self.master.switch_view("jeditor")
            else:
                logging.log(ALERT, "This command only works on HTTP flows!")
                return

addons = [EditBase64(ctx.master)]
