
import json
import unittest
from unittest.mock import MagicMock, patch

import receiver


class TestReceiverForwarding(unittest.TestCase):

    @patch("receiver.urllib.request.urlopen")
    def test_forward_event_adds_metadata_and_sends_http_post(
        self, mock_urlopen
    ):
        # Simulate a successful HTTP response from Logstash.
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        event = {
            "@timestamp": "2026-10-24T10:00:00Z",
            "event": {
                "id": "FIXED-0001",
                "dataset": "linux.auth",
                "original": "Example login event"
            },
            "message": "Failed SSH login"
        }

        status = receiver.forward_event(event)

        # Check the HTTP response.
        self.assertEqual(status, 200)

        # Check the required metadata.
        self.assertEqual(event["labels"]["ingest_mode"], "stream")
        self.assertEqual(
            event["labels"]["source_id"],
            "A3-Stream-Ingestion"
        )
        self.assertEqual(event["event_id"], "FIXED-0001")

        # Check that an HTTP POST was sent to Logstash.
        mock_urlopen.assert_called_once()
        request = mock_urlopen.call_args.args[0]

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.full_url, receiver.LOGSTASH_URL)
        self.assertEqual(
            request.get_header("Content-type"),
            "application/json"
        )

        # Check that the request body contains the event and metadata.
        payload = json.loads(request.data.decode("utf-8"))

        self.assertEqual(payload["event_id"], "FIXED-0001")
        self.assertEqual(payload["labels"]["ingest_mode"], "stream")
        self.assertEqual(
            payload["labels"]["source_id"],
            "A3-Stream-Ingestion"
        )


if __name__ == "__main__":
    unittest.main()
