import os
import subprocess

from mdecbase import Service


class RekoService(Service):
    """
    Reko decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        subprocess.run(['/opt/reko/decompile', path], check=True)
        reko_dir = path + '.reko'
        source_path = os.path.join(reko_dir, os.path.basename(path) + '_text.c')
        return open(source_path).read()
