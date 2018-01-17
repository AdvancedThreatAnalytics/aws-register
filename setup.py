from setuptools import setup

setup(
    name='aws_register',
    version='0.1',
    py_modules=['register'],
    install_requires=['boto3'],
    entry_points='''
        [console_scripts]
        aws-register=register:main
    ''',
)
