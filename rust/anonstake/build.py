import os
import subprocess

os.chdir(os.path.join(os.getcwd(), "..", "..", "build"))
subprocess.call(["cmake", ".."])
subprocess.call(["make", "fft"])
