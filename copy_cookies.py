"""Brute-force using a request as a template, fuzzing one parameter with a wordlist."""

import pyperclip
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

logger = logging.getLogger(__name__)
class CopyCookie:
    @command.command("copy_cookie")
    def copy_cookie(
        self,
        flows: Sequence[flow.Flow],
        index: int
    ) -> None:
        if len(flows) > 1:
            logging.log(ALERT, "Please specify a single flow, e.g. using `@focus`. Annoying, I know. Command not run.")
            return
        logging.debug("[copy_cookies.py] log level is set to debug or higher.")
        flowdex = 0
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                header_fields = f.request.headers.fields
                cookies = []
                for field in header_fields:
                    if field[0] == b'cookie':
                        cookies.append(field[1].decode('utf-8'))
                logging.info(f"cookies found: {cookies}")
                if index > len(cookies) - 1:
                    logging.log(ALERT, "There aren't that many cookies in this flow! Please choose a lower index.")
                    return
                pyperclip.copy(cookies[index])


addons = [CopyCookie()]
