from typing import BinaryIO
from logging import info
from collections.abc import Sequence
import asyncio

"""Take incoming HTTP requests and replay them with modified parameters."""
from mitmproxy import ctx, io, http, command, flow

tasks = set()

class MultiRepeater:
    def __init__(self, path: str) -> None:
        self.f: BinaryIO = open(path, "wb")
        self.w = io.FlowWriter(self.f)

    def done(self):
        self.f.close()

    @command.command("multirepeat")
    def multirepeat( self, flows: Sequence[flow.Flow], num_repeats: int) -> None:
        for flow in flows:
            flow_copy = flow.copy()
            this_task = asyncio.create_task(replay_n(flow_copy, self.w, num_repeats))
            tasks.add(this_task)
            this_task.add_done_callback(tasks.remove)

async def replay_n( flow: http.HTTPFlow , plug_writer: io.FlowWriter , num_repeats: int) -> None:
        for pl in range(num_repeats):
            await replay_once( flow , plug_writer )


async def replay_once( flow: http.HTTPFlow , plug_writer: io.FlowWriter ) -> None:
        
        try:
            flow_copy = flow.copy()
            plug_writer.add(flow_copy)
            if "view" in ctx.master.addons:
                ctx.master.commands.call("view.flows.duplicate",[flow_copy] )
            ctx.master.commands.call("replay.client", [flow_copy])
        except Exception as e:
            info(e)

addons = [MultiRepeater("test.writer")]

if __name__=='__main__':
    main()
