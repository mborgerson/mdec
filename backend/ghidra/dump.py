from ghidra.app.decompiler import DecompInterface
import traceback

out = open('out.c', 'w')
for f in currentProgram.getFunctionManager().getFunctions(True):
  try:
    di = DecompInterface()
    di.openProgram(currentProgram)
    out.write(di.decompileFunction(f, 0, None).getDecompiledFunction().getC())
    out.write('\n')
  except:
    out.write(traceback.format_exc())
    out.write('Failed to decompile %s' % str(f))
