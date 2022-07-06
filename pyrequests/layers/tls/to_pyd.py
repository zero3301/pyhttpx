import Cython.Build
from  distutils.core import setup

#ext = Cython.Build.cythonize('tls_session.py')
#to pyd
#setup(ext_modules=ext)


#console
#python to_pyd.py build


#to pyc
import py_compile
py_compile.compile('tls_session.py')