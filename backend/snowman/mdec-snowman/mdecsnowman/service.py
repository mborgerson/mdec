import os
import subprocess

from mdecbase import Service


class SnowmanService(Service):
    """
    Snowman decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        return subprocess.check_output(['/opt/snowman/bin/nocode', path]).decode('utf-8')
