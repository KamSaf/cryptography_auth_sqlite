import os
import pytest


def run_tests():
    test_directory = os.path.join(os.path.dirname(__file__), "tests")
    pytest.main(["-v", "-s", "--disable-warnings", test_directory])


if __name__ == "__main__":
    run_tests()
