import os
import subprocess
import tempfile

from mdecbase import Service


class GhidraService(Service):
    """
    Ghidra decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        original_cwd = os.getcwd()
        code = ''
        try:
            os.chdir(os.path.dirname(path))
            subprocess.run(['/opt/ghidra/support/analyzeHeadless', '.', 'temp_project', '-import', os.path.basename(path), '-postScript', '/opt/ghidra/dump.py'])
            code = open('out.c').read()
        finally:
            os.chdir(original_cwd)
        return code

    def version(self) -> str:
        original_cwd = os.getcwd()
        version = ''
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                subprocess.run(['/opt/ghidra/support/pythonRun', '/opt/ghidra/version.py'])
                version = open('version.txt').read()
        finally:
            os.chdir(original_cwd)
        return version
