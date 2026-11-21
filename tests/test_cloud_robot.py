import datetime as dt
import unittest
from scripts.cloud_robot import region_rank, update_state, stable_node_id

class CloudRobotTests(unittest.TestCase):
 def test_region_order(self):
  self.assertLess(region_rank("US"),region_rank("DE"));self.assertLess(region_rank("DE"),region_rank("JP"));self.assertLess(region_rank("JP"),region_rank("UNK"))
 def test_identity_ignores_display_name(self):
  a={"type":"vless","server":"example.com","port":443,"uuid":"secret","name":"A"};b=dict(a,name="B")
  self.assertEqual(stable_node_id(a),stable_node_id(b))
 def test_three_consecutive_days(self):
  state={"required_consecutive_days":3,"nodes":{}};candidate={"id":"abc","country":"US","protocol":"vless","name":"US Vless"}
  passed={"chatgpt":{"ok":True},"gemini":{"ok":True},"roblox":{"ok":True}};day=dt.date(2026,1,1)
  self.assertEqual(update_state(state,candidate,passed,day),("provisional",1))
  self.assertEqual(update_state(state,candidate,passed,day+dt.timedelta(days=1)),("provisional",2))
  self.assertEqual(update_state(state,candidate,passed,day+dt.timedelta(days=2)),("formal",3))
 def test_failure_resets_streak(self):
  state={"required_consecutive_days":3,"nodes":{"abc":{"last_test_date":"2026-01-01","pass_streak":2}}}
  candidate={"id":"abc","country":"US","protocol":"vless","name":"US Vless"}
  failed={"chatgpt":{"ok":True},"gemini":{"ok":False},"roblox":{"ok":True}}
  self.assertEqual(update_state(state,candidate,failed,dt.date(2026,1,2)),("rejected",0))
 def test_gap_resets_streak(self):
  state={"required_consecutive_days":3,"nodes":{"abc":{"last_test_date":"2026-01-01","pass_streak":2}}}
  candidate={"id":"abc","country":"US","protocol":"vless","name":"US Vless"}
  passed={"chatgpt":{"ok":True},"gemini":{"ok":True},"roblox":{"ok":True}}
  self.assertEqual(update_state(state,candidate,passed,dt.date(2026,1,3)),("provisional",1))
if __name__=="__main__":unittest.main()
