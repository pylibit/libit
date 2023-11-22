from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='libit',
    version='1.3.1',
    license='http://opensource.org/licenses/MIT',
    packages=find_packages(),
    install_requires=[
        'pycryptodome'
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],

    long_description=long_description,

    long_description_content_type="text/markdown",

    author='Mmdrza',

    include_package_data=True,

    author_email='Pymmdrza@gmail.com',

    description='libit package for python convert and generate wallet',

    url='https://github.com/libit',

    project_urls={
        'Bug Tracker': 'https://github.com/libit/issues',

        'Source Code': 'https://github.com/libit/libit',

        'Documentation': 'https://libit.github.com/libit/',

        'Website': 'https://mmdrza.com',

        'Medium': 'https://mdrza.medium.com'

    }

)