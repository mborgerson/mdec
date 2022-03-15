from __future__ import print_function

#
# This example tries to load a decompiler plugin corresponding to the current
# architecture (and address size) right after auto-analysis is performed,
# and then tries to decompile the function at the first entrypoint.
#
# It is particularly suited for use with the '-S' flag, for example:
# idat -Ldecompile.log -Sdecompile_entry_points.py -c file
#

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import idautils
import os.path

# becsause the -S script runs very early, we need to load the decompiler
# manually if we want to use it
def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False


def decompile_func(ea, outfile):
    print("Decompiling at: %X..." % ea)
    cf = ida_hexrays.decompile(ea)
    if cf:
        print("OK.")
        outfile.write(str(cf) + "\n")
    else:
        print("failed!")
        outfile.write("/* decompilation failure at %X */\n" % ea)


def main():
    print("Waiting for autoanalysis...")
    ida_auto.auto_wait()
    if init_hexrays():
        idbpath = idc.get_idb_path()
        cpath = os.path.join(os.path.dirname(idbpath), "out.c")
        with open(cpath, "w") as outfile:
            for ea in idautils.Functions():
                if idc.get_func_flags(ea) & (idc.FUNC_LIB | idc.FUNC_THUNK): continue
                decompile_func(ea, outfile)
    if idaapi.cvar.batch:
        print("All done, exiting.")
        ida_pro.qexit(0)


main()
