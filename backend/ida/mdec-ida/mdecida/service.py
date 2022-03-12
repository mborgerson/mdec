import os
import subprocess
import tempfile

from pathlib import Path
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

    def version(self) -> str:
        logpath = os.path.join(os.getcwd(), 'ida.log')

        # TODO: Is there a way to do this without creating an idb?
        with tempfile.TemporaryDirectory() as tmp:
            dummy_path = Path(tmp) / 'dummy'
            with open(dummy_path, 'wb') as dummy_file:
                dummy_file.write(b'\x00' * 256)
                subprocess.run(['/opt/ida/idat64', '-A', '-a',
                                '-S/opt/ida/version.py', '-L'+logpath, str(dummy_path)])
            try:
                return open(dummy_path.parent / 'version.txt').read().strip()
            except:
                print(open(logpath).read())
