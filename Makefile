.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -f coverage.xml
	rm -fr htmlcov/
	rm -fr .pytest_cache

lint: ## check style with flake8
	pre-commit run --all-files

test: ## run tests quickly with the default Python
	coverage run -m pytest tests
	coverage xml -o junit.xml

release: dist ## package and upload a release
	twine upload dist/*

dist: clean ## builds source and wheel package
	python -m build
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	python setup.py install

dev-install: clean ## install the package and test dependencies for local development
	python -m pip install --upgrade pip
	pip install -e ."[dev]"
	pip install -r examples/requirements.txt
	pre-commit install

docs-install: ## install packages for local documentation.
	python -m pip install --upgrade pip
	pip install -e ."[docs]"

docs: ## builds the documentation.
	$(MAKE) -C docs html

docs-serve: ## serves the documentation on 127.0.0.1:8000.
	$(MAKE) -C docs serve

new-env: ## creates environment for testing and documentation.
	python -m venv env
	source env/bin/activate && \
		pip install -e ."[test]" && \
		pip install -e ."[docs]"
	@echo "\n\nActivate environment by doing 'source env/bin/activate'.\n"
