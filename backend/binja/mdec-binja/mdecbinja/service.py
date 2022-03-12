from mdecbase import Service
from binaryninja import *


license = open('/opt/binaryninja/license.txt').read()
core_set_license(license)


class BinjaService(Service):
    """
    Binary Ninja decompiler as a service
    """

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.

        Based on https://github.com/Vector35/binaryninja-api/blob/2845ba6208ce3c29998a48df5073ed15a11ead77/rust/examples/decompile/src/main.rs
         - Where are the Python samples.....
        """
        out = []
        v = open_view(path)
        ds = DisassemblySettings()
        ds.set_option(DisassemblyOption.ShowAddress, False)
        ds.set_option(DisassemblyOption.WaitForIL, True)
        lv = LinearViewObject.language_representation(v, ds)
        for f in v.functions:
            c = LinearViewCursor(lv)
            c.seek_to_address(f.highest_address)
            last = v.get_next_linear_disassembly_lines(c.duplicate())
            first = v.get_previous_linear_disassembly_lines(c)
            for line in (first + last):
                out.append(str(line))
        return '\n'.join(out)
