from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

requirements_base = here / "requirements" / "base.txt"

with open("README.md") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()


def read_requirements(path):
    try:
        with path.open(mode="rt", encoding="utf-8") as fp:
            return list(filter(bool, (line.split("#")[0].strip() for line in fp)))
    except IndexError:
        raise RuntimeError(f"{path} is broken")


setup(
    author="Ali Aliyev",
    author_email="ali@aliev.me",
    python_requires=">=3.6.0",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Asynchronous OAuth 2.0 framework for Python 3",
    install_requires=read_requirements(requirements_base),
    license="MIT license",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="async_oauth2_provider",
    name="async_oauth2_provider",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    test_suite="tests",
    url="https://github.com/aliev/async-oauth2-provider",
)
