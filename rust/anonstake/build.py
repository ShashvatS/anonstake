import os
import subprocess
import sys
import shutil
import datetime

sys.stdout = open("output/python_build_log.txt", 'w')

os.chdir(os.path.join(os.getcwd(), "..", "..", "build"))
subprocess.call(["cmake", ".."])
subprocess.call(["make", "fft"])
shutil.copyfile(os.path.join(os.getcwd(), "libfft", "libfft.so"), os.path.join(sys.argv[1], "libfft.so"))

print(datetime.datetime.now())
print(sys.argv[1])
