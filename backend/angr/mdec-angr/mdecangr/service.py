import traceback

from mdecbase import Service
import angr


class AngrService(Service):
    """
    angr decompiler as a service
    """

    def decompile(self, path: str) -> str:
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

    def version(self) -> str:
        return '.'.join(str(i) for i in angr.__version__)
