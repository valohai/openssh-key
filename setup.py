import re

import setuptools

with open('./openssh_key/__init__.py', 'r') as infp:
    version = re.search(
        "__version__ = ['\"]([^'\"]+)['\"]", infp.read()
    ).group(1)

dev_dependencies = ['flake8', 'isort', 'pydocstyle', 'pytest-cov']

convert_dependencies = ['cryptography']

if __name__ == '__main__':
    setuptools.setup(
        name='openssh_key',
        description='Tools to deal with OpenSSH2 (RFC4716) keys',
        version=version,
        url='https://github.com/valohai/openssh_key',
        author='Valohai',
        maintainer='Aarni Koskela',
        maintainer_email='akx@iki.fi',
        license='MIT',
        install_requires=[],
        tests_require=dev_dependencies,
        extras_require={
            'dev': dev_dependencies,
            'convert': convert_dependencies,
        },
        packages=setuptools.find_packages('.'),
        include_package_data=True,
    )
