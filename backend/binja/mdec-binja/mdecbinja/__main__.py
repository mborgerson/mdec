import argparse
import tempfile
import traceback

from binaryninja import *
from aiohttp import web
import aiohttp


license = open('/opt/binaryninja/license.txt').read()
core_set_license(license)


def decompile(path: str) -> str:
    """
    Decompile all the functions in the binary located at `path`.

    Based on https://github.com/Vector35/binaryninja-api/blob/2845ba6208ce3c29998a48df5073ed15a11ead77/rust/examples/decompile/src/main.rs
     - Where are the Python samples.....
    """
    out = []
    v = open_view(path)
    ds = DisassemblySettings()
    ds.set_option(DisassemblyOption.ShowAddress, False)
    ds.set_option(DisassemblyOption.WaitForIL, True)
    lv = LinearViewObject.language_representation(v, ds)
    for f in v.functions:
        c = LinearViewCursor(lv)
        c.seek_to_address(f.highest_address)
        last = v.get_next_linear_disassembly_lines(c.duplicate())
        first = v.get_previous_linear_disassembly_lines(c)
        for line in (first + last):
            out.append(str(line))
    return '\n'.join(out)


class Service():
    """
    Binary Ninja decompiler as a service
    """

    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([web.post('/decompile', self.post_decompile)])

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
                decomp = decompile(f.name)
                resp_status = 200
            except:
                decomp = traceback.format_exc()
                resp_status = 500

            return web.Response(text=decomp, status=resp_status)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?', help='If provided, decompile given file and exit. Otherwise, start server')
    args = ap.parse_args()

    if args.file:
        print(decompile(args.file))
    else:
        s = Service()
        web.run_app(s.app, port=8000)


if __name__ == '__main__':
    main()
