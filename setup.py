import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="common-osint-model",
    version="0.3.0",
    author="Nils Kuhnert",
    description="Converting data from services like Censys and Shodan to a common data model.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/3c7/common-osint-model",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["DateTime", "mmh3", "cryptography"],
    entry_points={
        "console_scripts": [
            "convshodan=common_osint_model.cli:convshodan",
            "convcensys=common_osint_model.cli:convcensys",
            "convcensyscert=common_osint_model.cli:convcensyscert",
            "convcert=common_osint_model.cli:convcert"
        ],
    },
)
