import unittest

from card_helper import *

class Test_get_prefix_size(unittest.TestCase):
    """Tests cases for get_prefix_size function
    """
    def test_ndef_prefix(self):
        """Test that it can identify the NDEF headers
        """
        self.assertEqual(3, get_prefix_size(bytearray.fromhex('02413AFFFFFFFF')))

    def test_cuvex_prefix(self):
        """Test that it can identify the Cuvex legacy headers
        """
        self.assertEqual(9, get_prefix_size(bytearray(b'record_0:data')))

    def test_no_prefix(self):
        """Test that it can identify when no header is received
        """
        self.assertEqual(0, get_prefix_size(bytearray.fromhex('FFFFFFFF')))

class Test_process_card_version(unittest.TestCase):
    """Test cases for process_card_version function
    """

    def test_with_full_version(self):
        """Tests when the full version text is used
        """
        text_version = 'v1.2.3(4)'
        reference = Version(text_version, 1, 2, 3, '4')
        result = process_card_version(text_version)
        self.assertEqual(result.full_version, reference.full_version)
        self.assertEqual(result.major, reference.major)
        self.assertEqual(result.minor, reference.minor)
        self.assertEqual(result.patch, reference.patch)
        self.assertEqual(result.other, reference.other)

    def test_with_full_version(self):
        """Tests when the full version text is used
        """
        text_version = 'v1.2.3(4)'
        reference = Version(text_version, 1, 2, 3, '4')
        result = process_card_version(text_version)
        self.assertEqual(result.full_version, reference.full_version)
        self.assertEqual(result.major, reference.major)
        self.assertEqual(result.minor, reference.minor)
        self.assertEqual(result.patch, reference.patch)
        self.assertEqual(result.other, reference.other)