import unittest

from app import render_search_response, unsafe_user_lookup


class SampleApiTests(unittest.TestCase):
    def test_search_response_contains_query(self):
        self.assertIn("hello", render_search_response("hello"))

    def test_lookup_returns_known_user(self):
        self.assertEqual(unsafe_user_lookup("alice"), [("alice",)])


if __name__ == "__main__":
    unittest.main()
