import os
import subprocess
import sys
import shutil
import datetime

sys.stdout = open("python_build_log.txt", 'w')

os.chdir(os.path.join(os.getcwd(), "..", "..", "build"))
subprocess.call(["cmake", ".."])
subprocess.call(["make", "fft"])
shutil.copyfile(os.path.join(os.getcwd(), "libfft", "libfft.a"), os.path.join(sys.argv[1], "libfft.a"))

print(datetime.datetime.now())
