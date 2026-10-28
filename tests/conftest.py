"""Real native canaries require an explicit operator option; never enabled in CI."""


def pytest_addoption(parser):
    parser.addoption(
        "--run-native-canary",
        action="store_true",
        default=False,
        help="Opt in to synthetic Linux probes with a reviewed runtime",
    )
