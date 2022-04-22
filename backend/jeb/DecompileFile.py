#?description=Decompile a file provided to JEB
#?shortcut=
import os
import sys
import time
from com.pnfsoftware.jeb.util.io import IO
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units import INativeCodeUnit, UnitUtil
from com.pnfsoftware.jeb.core.units.code import ICodeUnit, ICodeItem
from com.pnfsoftware.jeb.core.output.text import ITextDocument
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, DexDecompilerExporter
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.util.base import ProgressCallbackAdapter
"""
Sample script for JEB Decompiler.

- This script decompiles all code units of the project
- If run on the command line, the provided input file will be analyzed
- It makes use of the 'decompiler exporter' objects to provide fast decompilation.
- The default settings (see below) is to decompile dex code only, not native code(s)

How to run (eg, on Windows):
  $ jeb_wincon.bat -c --srv2 --script=DecompileFile.py -- INPUT_FILE OUTPUT_DIR

For additional details, refer to:
https://www.pnfsoftware.com/jeb/manual/faq/#can-i-execute-a-jeb-python-script-from-the-command-line
"""
class DecompileFile(IScript):

  def run(self, ctx):
    self.ctx = ctx

    self.decompileDex = False
    self.decompileNative = True

    if not self.decompileDex and not self.decompileNative:
      print('Warning! Both decompileDex and decompileNative are set to false. Adjust your script and run it again.')
      return

    if isinstance(ctx, IGraphicalClientContext):
      self.outputDir = ctx.displayFolderSelector('Output folder')
      if not self.outputDir:
        print('Need an output folder')
        return
    else:
      argv = ctx.getArguments()
      if len(argv) < 2:
        print('Provide an input file and the output folder')
        return
      inputFile = argv[0]
      self.outputDir = argv[1]
      print('Processing file: %s...' % inputFile)
      ctx.open(inputFile)

    prj = ctx.getMainProject()
    assert prj, 'Need a project'

    t0 = time.time()
    for codeUnit in prj.findUnits(ICodeUnit):
      self.decompileCodeUnit(codeUnit)

    exectime = time.time() - t0
    print('Exectime: %f' % exectime)


  def decompileCodeUnit(self, codeUnit):
    # make sure the code unit is processed
    if not codeUnit.isProcessed():
      if not codeUnit.process():
        print('The code unit cannot be processed!')
        return

    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
      print('There is no decompiler available for code unit %s' % codeUnit)
      return

    outdir = os.path.join(self.outputDir, codeUnit.getName() + '_decompiled')
    print('Output folder: %s' % outdir)  # created only if necessary, i.e. some contents was exported

    if not((isinstance(codeUnit, INativeCodeUnit) and self.decompileNative) or (isinstance(codeUnit, IDexUnit) and self.decompileDex)):
      print('Skipping code unit: %s' % UnitUtil.buildFullyQualifiedUnitPath(codeUnit))
      return

    # DecompilerExporter object
    exp = decomp.getExporter()
    exp.setHeaderString('')
    exp.setOutputFolder(IO.createFolder(outdir))
    # limit to 1 minute max per method
    exp.setMethodTimeout(1 * 60000)
    # limit to 15 minutes (total)
    exp.setTotalTimeout(15 * 60000)
    # set a callback to output real-time information about what's being decompiled
    class DecompCallback(ProgressCallbackAdapter):
      def message(self, msg):
        print('%d/%d: %s' % (self.getCurrent(), self.getTotal(), msg))
    exp.setCallback(DecompCallback())
    # decompile & export
    if not exp.export():
      cnt = len(exp.getErrors())
      i = 1
      for sig, err in exp.getErrors().items():
        print('%d/%d DECOMPILATION ERROR: METHOD %s: %s' % (i, cnt, sig, err))
        i += 1
