from setuptools import setup, find_packages

from lenticrypt import VERSION

setup(
    name='lenticrypt',
    description='A simple cryptosystem that provides provable plausibly deniable encryption. Lenticrypt can generate a single ciphertext file such that different plaintexts are generated depending on which key is used for decryption.',
    url='https://github.com/ESultanik/lenticrypt',
    author='Evan Sultanik',
    version=VERSION,
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    python_requires='>=3.6',
    install_requires=[],
    extras_require={},
    entry_points={
        'console_scripts': [
            'lenticrypt = lenticrypt.__main__:main'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Topic :: Security :: Cryptography'
    ],
    test_suite="tests"
)
