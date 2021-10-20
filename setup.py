from setuptools import setup, find_packages

requirements = [ ]

test_requirements = ['pytest>=3', ]

setup(
    author="AIN Dev Team",
    author_email='dev@ainetwork.ai',
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="AI Network Client Library for Python3",
    install_requires=requirements,
    license="ISC license",
    long_description=open("README.md").read(),
    include_package_data=True,
    keywords='ain',
    name='ain',
    packages=find_packages(include=['ain', 'ain.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/dev-ainetwork/ain',
    version='0.1.0',
    zip_safe=False,
)
