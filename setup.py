import os
import subprocess
import sys

from distutils.command.build import build
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))


OPTIONS = [
    ('with-unit-tests', None, 'Enable yaramod unit tests.'),
    ('debug', None, 'Build debug configuration.')
]

BOOL_OPTIONS = [
    'with-unit-tests',
    'debug'
]


class WorkingDirectory:
    def __init__(self, dirpath):
        self.old_dirpath = os.getcwd()
        self.dirpath = dirpath

    def __enter__(self):
        os.chdir(self.dirpath)
        return self

    def __exit__(self, type, value, traceback):
        os.chdir(self.old_dirpath)


class BuildCommand(build):
    user_options = build_ext.user_options + OPTIONS
    boolean_options = build_ext.boolean_options + BOOL_OPTIONS

    def initialize_options(self):
        build.initialize_options(self)
        self.with_unit_tests = None
        self.debug = None


class BuildExtCommand(build_ext):
    user_options = build_ext.user_options + OPTIONS
    boolean_options = build_ext.boolean_options + BOOL_OPTIONS

    def initialize_options(self):
        build_ext.initialize_options(self)
        self.with_unit_tests = None
        self.debug = None

    def run(self):
        self.set_undefined_options('build',
                ('with_unit_tests', 'with_unit_tests'),
                ('debug', 'debug')
            )

        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            print('CMake is not installed on your system or it is not in PATH. Please, make sure CMake is accessible through PATH.', file=sys.stderr)
            return

        root_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        build_dir = os.path.join(root_dir, 'build')
        module_output_dir = os.path.dirname(os.path.realpath(self.get_ext_fullpath(self.extensions[0].name)))
        if 'configuration' in os.environ:
            config_name = os.environ['configuration']
        else:
            config_name = 'Debug' if self.debug else 'Release'

        os.makedirs(build_dir, exist_ok=True)

        with WorkingDirectory(build_dir):
            configure_cmd = ['cmake', '-DYARAMOD_PYTHON=ON', '-DPYTHON_EXECUTABLE={}'.format(sys.executable)]
            if 'CMAKE_GENERATOR' in os.environ:
                configure_cmd.append('-G{}'.format(os.environ['CMAKE_GENERATOR']))
            if 'win' in self.plat_name:
                configure_cmd.append('-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(config_name.upper(), module_output_dir))
                if 'CMAKE_GENERATOR' not in os.environ:
                    if self.plat_name == 'win-amd64':
                        configure_cmd.extend(['-A', 'x64'])
                    elif self.plat_name == 'win32':
                        configure_cmd.extend(['-A', 'x86'])
            else:
                configure_cmd.extend([
                    '-DCMAKE_BUILD_TYPE={}'.format(config_name),
                    '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={}'.format(module_output_dir)
                ])
            if self.with_unit_tests:
                configure_cmd.append('-DYARAMOD_TESTS=ON')
            configure_cmd.append(root_dir)

            build_cmd = ['cmake', '--build', '.', '--']
            if 'win' in self.plat_name:
                build_cmd.extend(['/m:{}'.format(os.cpu_count()), '/p:Configuration={}'.format(config_name)])
            else:
                build_cmd.append('-j{}'.format(os.cpu_count()))

            subprocess.check_call(configure_cmd)
            subprocess.check_call(build_cmd)

def get_long_description():
    if len(sys.argv) > 1 and 'dist' in sys.argv[1]:
        try:
            import pypandoc
            return pypandoc.convert_file(os.path.join(script_dir, 'README.md'), 'rst')
        except (ImportError, OSError):
            print('===> PANDOC is not installed on the system!', file=sys.stderr)
    return ''

setup(
    version='2.2.0',
    name='yaramod',
    description='Library for manipulation of YARA files.',
    long_description=get_long_description(),
    author='Marek Milkovic',
    author_email='marek.milkovic@avast.com',
    url='https://github.com/avast-tl/yaramod',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython'
    ],
    keywords='parser yara',
    python_requires='>=3',
    cmdclass={
        'build': BuildCommand,
        'build_ext': BuildExtCommand
    },
    ext_modules=[Extension(name='yaramod', sources=[])]
)
