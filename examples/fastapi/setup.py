from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

requirements_base = here / "requirements.txt"


def read_requirements(path):
    try:
        with path.open(mode="rt", encoding="utf-8") as fp:
            return list(filter(bool, (line.split("#")[0].strip() for line in fp)))
    except IndexError:
        raise RuntimeError(f"{path} is broken")


setup(
    name="fastapi_oauth2",
    python_requires=">=3.6.0",
    setup_requires=["setuptools_scm"],
    install_requires=read_requirements(requirements_base),
    include_package_data=True,
    package_data={},
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)
