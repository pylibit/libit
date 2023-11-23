from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='libit',
    version='1.6.3',
    license='http://opensource.org/licenses/MIT',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'ecdsa'
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],

    long_description=long_description,

    long_description_content_type="text/markdown",

    author='Mmdrza',

    keywords=['bitcoin', 'cryptography', 'python', 'library', 'crypto', 'libit', 'ethereum', 'tron'],

    include_package_data=True,

    author_email='Pymmdrza@gmail.com',

    description='Library Bitcoin package for python convert and generate wallet',

    url='https://github.com/pylibit',

    project_urls={
        'Bug Tracker': 'https://github.com/pylibit/issues',

        'Source Code': 'https://github.com/pylibit/libit',

        'Documentation': 'https://pylibit.github.io/libit/',

        'Website': 'https://mmdrza.com',

        'Medium': 'https://mdrza.medium.com'

    }

)