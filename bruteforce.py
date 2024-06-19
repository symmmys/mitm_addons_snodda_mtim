"""Brute-force using a request as a template, fuzzing one parameter with a wordlist."""

import logging
import subprocess
from collections.abc import Sequence
from typing import BinaryIO
from multiprocessing import Process

from mitmproxy import io
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import types
from mitmproxy.log import ALERT
from mitmproxy.net.http.http1 import assemble
from mitmproxy import exceptions

words_A = []
words_B = []
logger = logging.getLogger(__name__)
#these two functions just copypasta'd from mitmproxy/addons/export.py
def cleanup_request(f: flow.Flow) -> http.Request:
    if not getattr(f, "request", None):
        raise exceptions.CommandError("Can't export flow with no request.")
    assert isinstance(f, http.HTTPFlow)
    request = f.request.copy()
    request.decode(strict=False)
    return request

def raw_request(f: flow.Flow) -> bytes:
    request = cleanup_request(f)
    if request.raw_content is None:
        raise exceptions.CommandError("Request content missing.")
    return assemble.assemble_request(request)

def run_ffuf(arglist_in):
    subprocess.run(arglist_in)  

class BruteForce:
    @command.command("bruteforce")
    def bruteforce(
        self,
        flows: Sequence[flow.Flow],
        wordlist: str
    ) -> None:
        logging.debug("[bruteforce.py] log level is set to debug or higher.")
        flowdex = 0
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                this_filename = f"request_{flowdex}.mitm"
                this_outfile = open(this_filename, "wb")
                this_outfile.write(raw_request(f))
                this_outfile.close()
                
                this_ffuf_outfile = f"request_{flowdex}.ffuf.html"
                arglist = ["ffuf","-request",this_filename,"-w",wordlist,"-replay-proxy","http://127.0.0.1:8080","-mc","all","-o",this_ffuf_outfile,"-of","html"]
                p = Process(target=run_ffuf, args=(arglist,))
                p.start()
                p.join()
                flowdex = flowdex + 1

addons = [BruteForce()]
