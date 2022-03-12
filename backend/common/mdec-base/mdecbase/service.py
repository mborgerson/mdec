import tempfile
import traceback
import argparse

from aiohttp import web
import aiohttp


class Service:
    """
    Decompiler as a service
    """

    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([web.post('/decompile', self.post_decompile)])

    def decompile(self, path: str) -> str:
        raise NotImplementedError()

    async def post_decompile(self, request: aiohttp.web.BaseRequest) -> web.Response:
        reader = await request.multipart()
        binary = await reader.next()
        if binary is None:
            return web.Response(status=400)

        with tempfile.NamedTemporaryFile() as f:
            while True:
                chunk = await binary.read_chunk()
                if not chunk:
                    break
                f.write(chunk)
                f.flush()

            try:
                decomp = self.decompile(f.name)
                resp_status = 200
            except:
                decomp = traceback.format_exc()
                resp_status = 500

            return web.Response(text=decomp, status=resp_status)


def mdec_main(service: Service):
    """
    Common module main function
    """
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?', help='If provided, decompile given file and exit. Otherwise, start server')
    args = ap.parse_args()

    s = service()
    if args.file:
        print(s.decompile(args.file))
    else:
        web.run_app(s.app, port=8000)
