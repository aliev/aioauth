from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

requirements_base = here / "requirements" / "base.txt"


def read_requirements(path):
    try:
        with path.open(mode="rt", encoding="utf-8") as fp:
            return list(filter(bool, (line.split("#")[0].strip() for line in fp)))
    except IndexError:
        raise RuntimeError(f"{path} is broken")


setup(
    name="async_oauth2_provider",
    python_requires=">=3.5.0",
    setup_requires=["setuptools_scm"],
    install_requires=read_requirements(requirements_base),
    use_scm_version={
        "version_scheme": "guess-next-dev",
        "local_scheme": "dirty-tag",
        "write_to": "async_oauth2_provider/__init__.py",
        "write_to_template": '__version__ = "{version}"\n',
        "relative_to": __file__,
    },
    include_package_data=True,
    package_data={},
    packages=find_packages(where="async_oauth2_provider"),
    package_dir={"": "async_oauth2_provider"},
    author="Ali Aliyev",
    author_email="ali@aliev.me",
    url="https://aliev.me",
)
