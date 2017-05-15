import twiiter
import unittest
import json
import uuid


class TwiiterTestCase(unittest.TestCase):

    def setUp(self):
        twiiter.app.config['TESTING'] = True
        self.app = twiiter.app.test_client()

    def test_create_retrieve_update_delete_twiit(self):
        # Create Twiit
        rv = self.app.post('/twiit', data=dict(text='this is a test status'))
        assert rv.status_code == 200
        payload = json.loads(rv.data.decode())
        twiit_id = payload['id']
        assert str(uuid.UUID(twiit_id)) == twiit_id  # Validate uuid
        assert payload['text'] == 'this is a test status'

        # Retrieve Twiit
        rv = self.app.get('/twiit/'+twiit_id)
        assert rv.status_code == 200
        payload = json.loads(rv.data.decode())
        assert payload['id'] == twiit_id
        assert payload['text'] == 'this is a test status'

        # Update Twiit
        rv = self.app.put('/twiit/'+twiit_id,
                          data=dict(text='the text has been updated'))
        assert rv.status_code == 200
        payload = json.loads(rv.data.decode())
        assert 'updated_at' in payload  # Twiit as modified timestamp
        assert payload['text'] == 'the text has been updated'

        # Delete Twiit
        rv = self.app.delete('/twiit/'+twiit_id)
        assert rv.status_code == 200
        payload = json.loads(rv.data.decode())
        assert payload['id'] == twiit_id
        assert payload['status'] == 'deleted'

        rv = self.app.get('/twiit/'+twiit_id)
        assert rv.status_code == 404


if __name__ == '__main__':
    unittest.main()
