from ghidra.framework import Application
import traceback

out = open('version.txt', 'w')
out.write(Application.getApplicationVersion() + ' ' +
          Application.getApplicationReleaseName() + '\n')
