from pathlib import Path

from setuptools import setup, find_packages

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
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    "Topic :: Internet :: WWW/HTTP",
]

require_dev = [
    "async-asgi-testclient==1.4.4",
    "pre-commit==2.13.0",
    "pytest==5.4.3",
    "pytest-asyncio==0.12.0",
    "pytest-cov==2.9.0",
    "pytest-env==0.6.2",
    "pytest-sugar==0.9.3",
    "testfixtures==6.14.1",
    "bump2version==0.5.11",
    "twine==1.14.0",
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
    python_requires=">=3.6.0",
    classifiers=classifiers,
    extras_require={
        "dev": require_dev,
        "docs": require_docs,
    },
    include_package_data=True,
    keywords="asyncio oauth2 oauth",
    packages=find_packages(exclude=["tests"]),
    project_urls={"Source": about["__url__"]},
)
