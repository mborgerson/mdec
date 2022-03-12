import os
import subprocess

from mdecbase import Service


class IdaService(Service):
    """
    IDA decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        logpath = os.path.join(os.getcwd(), 'ida.log')
        subprocess.run(['/opt/ida/idat64', '-A', '-S/opt/ida/decompile_all.py', '-L'+logpath, path])
        try:
            outpath = os.path.join(os.path.dirname(path), 'out.c')
            return open(outpath).read()
        except:
            print(open(logpath).read())
