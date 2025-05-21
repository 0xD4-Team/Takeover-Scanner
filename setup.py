from setuptools import setup, find_packages

setup(
    name="Takeover-Scanner",
    version="3.0.0",
    description="Advanced Domain Takeover Vulnerability Scanner",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="0xD4 Team",
    author_email="contact@0xD4.team",
    url="https://github.com/0xD4-Team/Takeover-Scanner",
    packages=find_packages(),
    install_requires=[
        'requests>=2.28.1',
        'beautifulsoup4>=4.11.1',
        'dnspython>=2.2.1',
        'python-whois>=0.8.0',
        'concurrent-log-handler>=0.9.20',
        'fake-useragent>=1.1.1',
        'tldextract>=3.4.0'
    ],
    entry_points={
        'console_scripts': [
            '0xD4-scanner=src.scanner:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
    ],
    python_requires='>=3.8',
)