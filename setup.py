from setuptools import setup, find_packages

setup(
    name="ghidrabridge",
    version="0.1.0",
    author="James Stevenson",
    author_email="opensource@JamesStevenson.me",
    description="A Python interface for automating Ghidra tasks.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/user1342/GhidraBridge",
    packages=find_packages(),
    install_requires=[
        "tqdm",
    ],
    python_requires='>=3.6',
)
