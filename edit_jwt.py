"""Edit a JWT found in the focused request using the mitmproxy grideditor"""

import pyperclip
import re
from base64 import urlsafe_b64encode, urlsafe_b64decode
import logging
import subprocess
from collections.abc import Sequence
from typing import BinaryIO

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

logger = logging.getLogger(__name__)
jwt_regex = re.compile(b'(.*=)([A-Za-z0-9_-]{2,})((?:\.[A-Za-z0-9_-]{2,}))((?:\.[A-Za-z0-9_-]{2,}))')
just_jwt_regex = re.compile(b'^([A-Za-z0-9_-]{2,})((?:\.[A-Za-z0-9_-]{2,}))((?:\.[A-Za-z0-9_-]{2,}))$')

def padded_decode(bytes_in):
    bytes_in = bytes_in.rstrip(b'=')
    padding = ( - len(bytes_in) % 4 )
    bytes_in = bytes_in + (b"=" * padding)
    bytes_out = urlsafe_b64decode(bytes_in)
    return bytes_out

def depadded_encode(bytes_in):
    return urlsafe_b64encode(bytes_in).strip(b"=")

class JWTEditor(HeaderEditor):
    title = "Edit one (or more) JWT(s) found in the focused request"

    def get_data(self, flow):
        dummy_data = []
        match_index = 0
        for header_tuple in flow.request.headers.fields:
            found_jwt = jwt_regex.match(header_tuple[1])
            if found_jwt and len(found_jwt.groups()) > 3:
                jwt_dict = dict()
                prefix = found_jwt.group(1)
                header=found_jwt.group(2)
                payload=found_jwt.group(3).lstrip(b".")
                signature=found_jwt.group(4).lstrip(b".")
                decoded_jwt_header = padded_decode(header)
                decoded_payload = padded_decode(payload)
                decoded_signature = padded_decode(signature)
                dummy_data.append((f"http_header_{match_index}".encode(),header_tuple[0]))
                dummy_data.append((f"prefix_{match_index}".encode(),prefix))
                dummy_data.append((f"jwt_header_{match_index}".encode(),decoded_jwt_header))
                dummy_data.append((f"payload_{match_index}".encode(),decoded_payload))
                dummy_data.append((f"signature_{match_index}".encode(),decoded_signature))
        return dummy_data

    def set_data(self, vals, flow):
        match_index = 0
        match_dict = dict()
        http_header_check = f"http_header_{match_index}".encode()
        prefix_check = f"prefix_{match_index}".encode()
        jwt_header_check = f"jwt_header_{match_index}".encode()
        payload_check = f"payload_{match_index}".encode()
        signature_check = f"signature_{match_index}".encode()
        for component_tuple in vals:
            if component_tuple[0] == http_header_check:
                this_http_header = component_tuple[1]
                match_dict[this_http_header] = b""
            if component_tuple[0] == signature_check:
                match_dict[this_http_header] = match_dict[this_http_header] + b"." + depadded_encode(component_tuple[1])
                match_index = match_index + 1
                http_header_check = f"http_header_{match_index}".encode()
                prefix_check = f"prefix_{match_index}".encode()
                jwt_header_check = f"jwt_header_{match_index}".encode()
                payload_check = f"payload_{match_index}".encode()
                signature_check = f"signature_{match_index}".encode()
            if component_tuple[0] == payload_check:
                match_dict[this_http_header] = match_dict[this_http_header] + b"." + depadded_encode(component_tuple[1])
            if component_tuple[0] == jwt_header_check:
                match_dict[this_http_header] = match_dict[this_http_header] + depadded_encode(component_tuple[1])
            if component_tuple[0] == prefix_check:
                match_dict[this_http_header] = match_dict[this_http_header] + component_tuple[1]
        for http_header in match_dict:
            flow.request.headers[http_header] = match_dict[http_header]

class EditJWT(ConsoleAddon):
    @command.command("edit_jwt")
    def edit_jwt(
        self,
        flows: Sequence[flow.Flow],
        index: int
    ) -> None:
        if len(flows) > 1:
            logging.log(ALERT, "Please specify a single flow, e.g. using `@focus`. Annoying, I know. Command not run.")
            return
        logging.debug("[edit_jwts.py] log level is set to debug or higher.")
        flowdex = 0
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                main_window = self.master.window
                jeditor = JWTEditor(self.master)
                main_window.stacks[0].windows["jeditor"] = jeditor
                self.master.switch_view("jeditor")
            else:
                logging.log(ALERT, "This command only works on HTTP flows!")
                return



addons = [EditJWT(ctx.master)]
