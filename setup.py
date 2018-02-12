import os
import subprocess
import sys

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class WorkingDirectory:
    def __init__(self, dirpath):
        self.old_dirpath = os.getcwd()
        self.dirpath = dirpath

    def __enter__(self):
        os.chdir(self.dirpath)
        return self

    def __exit__(self, type, value, traceback):
        os.chdir(self.old_dirpath)


class BuildExtCommand(build_ext):
    def run(self):
        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            print('CMake is not installed on your system or it is not in PATH. Please, make sure CMake is accessible through PATH.', file=sys.stderr)
            return

        root_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        build_dir = os.path.join(root_dir, 'build')
        module_output_dir = os.path.dirname(os.path.realpath(self.get_ext_fullpath(self.extensions[0].name)))

        os.makedirs(build_dir, exist_ok=True)

        with WorkingDirectory(build_dir):
            subprocess.check_call(['cmake', '-DCMAKE_BUILD_TYPE=Debug', '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={}'.format(module_output_dir), '-DYARAMOD_PYTHON=ON', root_dir])
            subprocess.check_call(['cmake', '--build', '.'])

setup(
    version='0.9.0',
    name='yaramod',
    description='Library for manipulation with YARA files.',
    author='Marek Milkovic <marek.milkovic@avast.com>',
    cmdclass={
        'build_ext': BuildExtCommand
    },
    ext_modules=[Extension(name='yaramod', sources=[])]
)
