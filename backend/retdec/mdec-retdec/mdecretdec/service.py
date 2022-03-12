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

    def version(self) -> str:
        output = subprocess.check_output(['/opt/retdec/bin/retdec', '--version']).decode('utf-8')
        lines = output.split('\n')
        version_lines = [l for l in lines if l.startswith('RetDec version')]
        assert len(version_lines) > 0
        # 'RetDec version :  v4.0-414-gc990727e'
        version_line = version_lines[0].strip()
        assert version_line.startswith('RetDec version :  ')
        return version_line.split(':')[1].strip()
