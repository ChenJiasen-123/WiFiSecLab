import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"src"))
from wifiseclab.lifecycle.key_evidence import parse_trace, analyze
PEER="02:00:00:00:00:01"
def line(pid,event,body):
    return f"hostapd-{pid} [001] ..... 1.123456: {event}: {body}"
def request(pid=1,phy="phy10",op="rdev_add_key"):
    return line(pid,op,f"{phy}, wdev(1), link_id: -1, key_index: 0, pairwise: true, mac addr: {PEER}")
def ret(pid=1,phy="phy10",code=0):
    return line(pid,"rdev_return_int",f"{phy}, returned: {code}")
STATS={"cpu0":"overrun: 0\ncommit overrun: 0\ndropped events: 0\n"}
def fulltrace():
    rows=[request(),ret(),line(99,"tracing_mark_write","connect"),request(op="rdev_del_key"),ret(),line(99,"tracing_mark_write","disconnect"),request(),ret(),line(99,"tracing_mark_write","reconnect")]
    return "\n".join(rows)
class KeyEvidenceTests(unittest.TestCase):
    def test_full_lifecycle(self):
        r=analyze(fulltrace(),"phy10",PEER,STATS)
        self.assertEqual(set(r["checks"].values()),{"observed"})
        self.assertIn("physical firmware key state",r["not_verified"])
    def test_pid_interleaving(self):
        ops,_=parse_trace("\n".join([request(1),request(2),ret(2,code=-2),ret(1)]))
        self.assertEqual([o["return_code"] for o in ops],[0,-2])
    def test_other_entry_invalidates_pair(self):
        ops,_=parse_trace("\n".join([request(),line(1,"rdev_change_station","phy10"),ret()]))
        self.assertIsNone(ops[0]["return_code"])
    def test_wrong_phy_return(self):
        ops,_=parse_trace(request()+"\n"+ret(phy="phy11"))
        self.assertIsNone(ops[0]["return_code"])
    def test_missing_return(self):
        ops,_=parse_trace(request())
        self.assertIsNone(ops[0]["return_code"])
    def test_trace_loss_disables_confirmation(self):
        stats={"cpu0":"overrun: 2\ncommit overrun: 0\ndropped events: 0"}
        self.assertEqual(set(analyze(fulltrace(),"phy10",PEER,stats)["checks"].values()),{"unknown_trace_loss"})
    def test_missing_stats_unknown(self):
        self.assertEqual(set(analyze(fulltrace(),"phy10",PEER,{})["checks"].values()),{"unknown_trace_loss"})
    def test_not_found_not_success(self):
        text=fulltrace().replace("returned: 0","returned: -2")
        self.assertEqual(set(analyze(text,"phy10",PEER,STATS)["checks"].values()),{"not_confirmed"})
    def test_other_peer_not_used(self):
        self.assertEqual(set(analyze(fulltrace(),"phy10","02:00:00:00:00:02",STATS)["checks"].values()),{"not_confirmed"})
    def test_missing_marker_unknown(self):
        self.assertEqual(set(analyze(request()+"\n"+ret(),"phy10",PEER,STATS)["checks"].values()),{"unknown"})
