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

    def version(self) -> str:
        output = subprocess.check_output(['/opt/reko/decompile', '--version']).decode('utf-8')
        # 'Decompile.exe version 0.10.1.0 (git:426370b)\n'
        version_line = output.strip()
        assert version_line.startswith('Decompile.exe version ')
        return version_line.split(' ')[2].strip()
