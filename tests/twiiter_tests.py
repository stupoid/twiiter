import twiiter
import unittest
import random
import string


class TwiiterTestCase(unittest.TestCase):

    def setUp(self):
        twiiter.app.config['TESTING'] = True
        self.app = twiiter.app.test_client()

    def test_main_page(self):
        rv = self.app.get('/', follow_redirects=True)
        assert rv.status_code == 200

    def test_users_page(self):
        rv = self.app.get('/users', follow_redirects=True)
        assert rv.status_code == 200

    def test_tag_page(self):
        valid_chars = string.ascii_letters+string.digits + '_'
        tag_length = random.randint(1,9)
        random_tag = ''.join(random.SystemRandom().choice(valid_chars) for _ in range(tag_length))
        rv = self.app.get('/tag/{}'.format(random_tag), follow_redirects=True)
        assert rv.status_code == 200

        invalid_chars = ['~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(',
                         ')', '-', '+', '=', '{', '}', '[', ']', '|', '\\', ':',
                         ';', '"', ',', '.', '<', '>']

        for invalid_char in invalid_chars:
            rv = self.app.get('/tag/{}'.format(invalid_char+random_tag), follow_redirects=True)
            assert rv.status_code == 400

if __name__ == '__main__':
    unittest.main()
