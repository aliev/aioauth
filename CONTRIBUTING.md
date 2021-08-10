All contributions are welcome – especially:

- documentation,
- bug reports and issues,
- code contributions.

### Code

If you'd like to actively develop or help maintain this project then there are existing tests against which you can test the library with. Typically, this looks like

- `git clone git@github.com:aliev/aioauth.git`
- `cd aioauth`
- `python -mvenv env`
- `source env/bin/activate`
- `make dev-install`

`make dev-install` will also install all the required packages that will allow you to adhere to the code styling guide of `aioauth`.

Basically we use the `black` and `flake8` packages for code formatting, `pre-commit` package will check the code formatting before your first commit is made.

To automatically correct the formatting you can run the command inside the repository root:

```
pre-commit run --all-files
```

Running tests:

```
make test
```

the output result will also show the current coverage, please make sure the coverage is not below `99%`
