"""Setup script for automactc"""
import os
import re

from setuptools import find_packages, setup

HERE = os.path.dirname(__file__)


def get_version():
    version_re = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
    init = open(os.path.join(HERE, 'automactc', '__init__.py')).read()
    return version_re.search(init).group(1)


setup(
    name='automactc',
    version=get_version(),
    description='AutoMacTC: Automated Mac Forensic Triage Collector',
    long_description=open(os.path.join(HERE, 'README.md')).read(),
    author='Kshitij Kumar',
    author_email='kshitij.kumar@crowdstrike.com',
    url='https://github.com/CrowdStrike/automactc',
    entry_points={
        'console_scripts': [
            'automactc=automactc.automactc:main'
        ]
    },
    install_requires=[
        'pyobjc==5.2',
        'python-dateutil==2.8.0',
        'pytz==2019.1',
        'xattr==0.9.6'
    ],
    packages=find_packages(),
    zip_safe=True
)
