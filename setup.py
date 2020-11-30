import setuptools

with open('README.md', 'r') as desc:
    long_desc = desc.read()

reqs = []
with open('requirements.txt', 'r') as req:
    reqs.append(req.read())

setuptools.setup(
        name = 'MFASweep.py',
        version = '1.0.0',
        author = 'Casper G. Nielsen',
        author_email = 'whopsec@protonmail.com',
        description = 'Test Azure environment for MFA misconfigurations ',
        long_description = long_desc,
        long_description_content_type = 'text/markdown',
        url = 'https://github.com/CasperGN/MFASweep.py',
        packages = setuptools.find_packages(),
        install_requires = reqs, 
        include_package_data = True,
        classifiers = [
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: MIT License',
            'Environment :: Console'
        ],
        keywords='pentesting enumeration',
        python_requires = '>=3.4',
)