#!/usr/bin/env python

from distutils.core import setup

setup(
        name='smallsocks',
        version='0.1.0a1',
        author='Michal Belica',
        author_email='devel@beli.sk',
        url='https://github.com/beli-sk/smallsocks',
        description='Small SOCKS protocol server implementation in Python',
        classifiers=[
            'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
            'Intended Audience :: System Administrators',
            'Environment :: No Input/Output (Daemon)',
            'Development Status :: 3 - Alpha',
            'Operating System :: POSIX',
            'Topic :: System :: Networking',
            'Programming Language :: Python',
            ],
        license='GNU General Public License v3 or later (GPLv3+)',

        packages=['smallsockslib'],
        scripts=['smallsocks'],
        data_files=[
            ('/etc', ['smallsocks.conf']),
            ('/etc/init', ['init/smallsocks.conf']),
            ('/etc/default', ['init/smallsocks']),
            ('share/doc/smallsocks', ['LICENSE', 'README.md']),
            ]
        )
