import unittest

from lenticrypt import utils


class TestUtils(unittest.TestCase):
    def test_frozen_dict(self):
        source_dict = {chr(i): i for i in range(ord('a'), ord('a') + 26)}

        d = utils.FrozenDict(source_dict)

        self.assertEqual(source_dict, d)
        self.assertEqual(len(d), 26)

        # Make sure item assignment raises an exception:
        def assignment(d=d):
            d['A'] = 1337
        self.assertRaises(TypeError, assignment)

        # Make sure the hashing works by adding the same element twice into a set:
        self.assertEqual(len(frozenset([d, d])), 1)


if __name__ == '__main__':
    unittest.main()
