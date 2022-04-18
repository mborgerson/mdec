import traceback
import r2pipe
import subprocess

from mdecbase import Service

class R2decService(Service):
    """
    r2dec as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the function in the binary located at `path`.
        """
        r2 = r2pipe.open(path, flags=['-e bin.cache=true'])
        r2.cmd('a'*6)
        funcs = [func['name'] for func in r2.cmdj('aflj')]

        includes = set()
        out = []

        for func in funcs:
            try:
                dec = r2.cmd(f'pdd @{func}')
                [includes.add(line + '\n') for line in dec.splitlines() if line.startswith('#include')]
                out.append('\n'.join([line for line in dec.splitlines() if not line.startswith('#include')]).replace('/* r2dec pseudo code output */\n', '')+'\n')
            except:
                out.append(f'/* Decompilation of {func} failed:\n{traceback.format_exc()}\n*/')


        return '\n'.join(includes) + '\n' + '\n'.join(out)

    def version(self) -> str:
        return subprocess.run(['/usr/local/bin/r2', '-v'], stdout=subprocess.PIPE).stdout.splitlines()[0].split()[1].decode('utf-8', 'ignore')

