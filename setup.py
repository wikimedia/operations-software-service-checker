from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()

version = '0.2.1'

install_requires = [
    'urllib3>=1.7',
    'PyYAML>=3.11',
    'gevent>=1.1',
    'statsd>=3.0',
]

test_requires = [
    'mock',
    'nose',
]

setup(
    name='servicechecker',
    version=version,
    description="An automatic monitoring tool for swagger-based webservices",
    long_description=README,
    author='Giuseppe Lavagetto',
    author_email='glavagetto@wikimedia.org',
    url='http://github.com/wikimedia/service_checker',
    license='GPL',
    packages=find_packages(),
    zip_safe=False,
    install_requires=install_requires,
    tests_require=test_requires,
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'service-checker-swagger = servicechecker.swagger:main'
        ]
    },
)
