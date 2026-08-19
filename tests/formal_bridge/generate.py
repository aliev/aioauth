import argparse

from tests.formal_bridge.rfc6749 import run_quint_generate_traces


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Quint ITF traces.")
    parser.add_argument("--n-traces", type=int, default=100)
    args = parser.parse_args()

    run_quint_generate_traces(n_traces=args.n_traces)


if __name__ == "__main__":
    main()
