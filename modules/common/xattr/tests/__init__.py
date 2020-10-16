import os
import sys
import unittest


def all_tests_suite():
    suite = unittest.TestLoader().loadTestsFromNames([
        'xattr.tests.test_xattr',
    ])
    return suite


def main():
    runner = unittest.TextTestRunner()
    suite = all_tests_suite()
    runner.run(suite)


if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    main()
