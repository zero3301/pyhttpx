import Cython.Build

ext = Cython.Build.cythonize('test.py')

from  distutils.core import setup

setup(ext_modules=ext)


#console
#python to_pyd.py build