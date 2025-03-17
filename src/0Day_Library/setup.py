from setuptools import setup, find_packages

setup(
    name="ctr_python",
    version="0.1.0",
    author="Beniamin Jablonski",
    author_email="benjablonski@hotmail.com",
    description="First attempt to implement CTR as python library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/wiggly1993/Python_Implementation_ComputersAndSecurity_RoboticsCaseStudies_Cut-The-Rope/tree/main/src",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "networkx==3.4.2",
        "numpy==2.1.2",
        "scipy==1.14.1",
        "matplotlib==3.9.2",
    ],
    include_package_data=True,
)