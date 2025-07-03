# setup.py
from setuptools import setup, find_packages

setup(
    name='rebel_nmap',
    version='2.0',
    author='Rebel Genius',
    author_email='rebel@underground.net',
    description='Advanced Network Scanning Toolkit',
    long_description='Stealthy network reconnaissance with evasion techniques',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.4.5',
        'requests',
        'pywin32; platform_system=="Windows"',
        'python-nmap',
        'colorama'
    ],
    entry_points={
        'console_scripts': [
            'rebelmap = rebel_nmap.main:main'  # تم التصحيح هنا
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GPLv3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    include_package_data=True
)