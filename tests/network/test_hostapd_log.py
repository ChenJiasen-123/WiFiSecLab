import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"src"))
from wifiseclab.network.hostapd_log import parse_log
class LogTests(unittest.TestCase):
    def test_explicit_events_only(self):
        text="wlan2: AP-STA-CONNECTED 02:00:00:00:00:01\nnoise set_key\nwlan2: STA 02:00:00:00:00:01 WPA: pairwise key handshake completed (RSN)\nwlan2: AP-STA-DISCONNECTED 02:00:00:00:00:01"
        events=parse_log(text)
        self.assertEqual([e["kind"] for e in events],["peer_connected","pairwise_handshake_completed","peer_disconnected"])
        self.assertEqual(events[1]["evidence"],"hostapd.log:3")
    def test_empty_or_unrecognized(self):
        self.assertEqual(parse_log("driver key install request"),[])
