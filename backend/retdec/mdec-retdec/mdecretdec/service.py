import os
import subprocess

from mdecbase import Service


class RetdecService(Service):
    """
    RetDec decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        subprocess.check_output(['/opt/retdec/bin/retdec-decompiler', path]).decode('utf-8')
        return open(path + '.c').read()
