from pathlib import Path

from setuptools import setup

here = Path(__file__).parent
about = {}

with open(here / "aioauth" / "__version__.py", "r") as f:
    exec(f.read(), about)

with open("README.md") as readme_file:
    readme = readme_file.read()

classifiers = [
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python",
    "Topic :: Internet",
    "Topic :: Software Development :: Libraries :: Application Frameworks",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Software Development :: Libraries",
    "Topic :: Software Development",
    "Typing :: Typed",
    "Development Status :: 1 - Planning",
    "Environment :: Web Environment",
    "Framework :: AsyncIO",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3 :: Only",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    "Topic :: Internet :: WWW/HTTP",
]

require_dev = [
    "async-asgi-testclient==1.4.8",
    "pre-commit==2.16.0",
    "pytest==6.2.5",
    "pytest-asyncio==0.16.0",
    "pytest-cov==3.0.0",
    "pytest-env==0.6.2",
    "pytest-sugar==0.9.4",
    "testfixtures==6.18.3",
    "twine==3.7.1",
    "wheel",
]

require_docs = [
    "sphinx",
    "sphinx-copybutton",
    "sphinx-autobuild",
    "m2r2",
    "sphinx-rtd-theme",
]

setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    license=about["__license__"],
    package_data={"aioauth": ["py.typed"]},
    python_requires=">=3.7.0",
    classifiers=classifiers,
    install_requires=["typing_extensions"],
    extras_require={
        "fastapi": ["aioauth-fastapi>=0.0.1"],
        "dev": require_dev,
        "docs": require_docs + require_dev,
    },
    include_package_data=True,
    keywords="asyncio oauth2 oauth",
    packages=["aioauth"],
    project_urls={"Source": about["__url__"]},
)
