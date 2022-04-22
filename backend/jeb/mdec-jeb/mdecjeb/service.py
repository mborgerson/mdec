import os
import subprocess
import tempfile
import traceback

from mdecbase import Service

jeb_version = subprocess.check_output('/opt/jeb/jeb_linux.sh -c --license | head -n1', shell=True, encoding='utf-8').strip().split()[1]

class JebService(Service):
    """
    JEB decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        original_cwd = os.getcwd()
        code = ''

        try:
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run(f'/opt/jeb/jeb_linux.sh -c --srv2 --script=/opt/jeb/DecompileFile.py -- {path} {tmp}', shell=True)
                for root, dirs, files in os.walk(os.path.join(tmp)):
                    for f in files:
                        code += open(os.path.join(root, f)).read() + '\n'
        except:
            code = traceback.format_exc()

        return code

    def version(self) -> str:
        return jeb_version
