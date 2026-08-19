import asyncio

from tests.formal_bridge.rfc6749 import replay_all_traces


def main() -> None:
    checked = asyncio.run(replay_all_traces())
    if checked == 0:
        raise SystemExit("no formal trace states found to replay")
    print(f"replayed {checked} formal states")


if __name__ == "__main__":
    main()
