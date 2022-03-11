import argparse
import tempfile
import traceback

from aiohttp import web
import aiohttp
import angr


def decompile(path: str) -> str:
    """
    Decompile all the functions in the binary located at `path`.
    """
    p = angr.Project(path, auto_load_libs=False, load_debug_info=True)
    cfg = p.analyses.CFG(normalize=True,
                         resolve_indirect_jumps=True,
                         data_references=True,
                         cross_references=True
                         )
    p.analyses.CompleteCallingConventions(
        cfg=cfg,
        recover_variables=True,
        analyze_callsites=True
        )
    funcs = [func for func in cfg.functions.values()
              if not func.is_plt
              and not func.is_simprocedure
              and not func.alignment
              ]
    out = []
    for func in funcs:
        try:
            dec = p.analyses.Decompiler(func)
            out.append(dec.codegen.text)
        except:
            out.append('/* Decompilation of %s failed:\n%s\n*/' % (func, traceback.format_exc()))

    return '\n'.join(out)


class Service():
    """
    angr decompiler as a service
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
