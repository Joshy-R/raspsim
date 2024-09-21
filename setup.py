from setuptools import setup

setup(
    name="raspsim",
    version="0.1.1",
    author="Your Name",
    author_email="konrad@schoeller-und-scoeller.de",
    packages=[""],
    package_dir={"": "."},
    package_data={"": ["raspsim.cpython-312-x86_64-linux-gnu.so", "stubs/raspsim.pyi"]},
)
