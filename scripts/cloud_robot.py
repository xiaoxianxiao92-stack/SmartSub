#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud-side strict admission gate for SmartSub."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, re, subprocess, sys, tempfile, time, urllib.parse
from pathlib import Path
import yaml
SCRIPT_DIR=Path(__file__).resolve().parent
sys.path.insert(0,str(SCRIPT_DIR))
from generate_mihomo_config import build_proxy, build_config
APP_PROBES=(
 ("chatgpt","https://chatgpt.com/backend-api/me",{200,301,302,401}),
 ("gemini","https://gemini.google.com/",{200,301,302}),
 ("roblox","https://www.roblox.com/",{200,301,302}),
)
EUROPE={"GB","DE","FR","NL","BE","CH","AT","SE","NO","DK","FI","IE","ES","IT","PT","PL","CZ","RO","BG","GR","HU","SK","SI","HR","LT","LV","EE","IS","LU","UA"}
ASIA={"JP","KR","TW","SG","HK","MY","TH","IN","ID","PH","VN","KH","LA","BD","NP","LK","PK","MN"}
def utc_now(): return dt.datetime.now(dt.timezone.utc)
def utc_date(): return utc_now().date()
def extract_country(uri,proxy):
 label=urllib.parse.unquote(urllib.parse.urlsplit(uri).fragment or "")
 m=re.search(r"\b([A-Z]{2})\b",label)
 if m:return m.group(1)
 m=re.search(r"(?:^|[-_ ])([A-Z]{2})(?:[-_ ]|$)",str(proxy.get("name","")))
 return m.group(1) if m else "UNK"
def region_rank(country):
 if country=="US":return 0
 if country in EUROPE:return 1
 if country in ASIA:return 2
 return 3
def stable_node_id(proxy):
 identity={k:v for k,v in proxy.items() if k!="name"}
 raw=json.dumps(identity,sort_keys=True,ensure_ascii=False,separators=(",",":"))
 return hashlib.sha256(raw.encode()).hexdigest()
def read_candidates(path,limit):
 candidates,errors=[],[]
 seen=set()
 for line_no,raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(),1):
  uri=raw.strip().replace("&amp;","&")
  if not uri or uri.startswith("#"):continue
  try:
   proxy=build_proxy(uri); country=extract_country(uri,proxy); node_id=stable_node_id(proxy)
   if node_id in seen:continue
   seen.add(node_id)
   candidates.append({"id":node_id,"uri":uri,"proxy":proxy,"country":country,"protocol":proxy.get("type","unknown"),"name":urllib.parse.unquote(urllib.parse.urlsplit(uri).fragment) or f"{country} {proxy.get('type', 'node').upper()} {line_no}"})
  except Exception as exc:errors.append({"line":line_no,"error":str(exc)})
 candidates.sort(key=lambda n:(region_rank(n["country"]),n["country"],n["protocol"],n["name"]))
 return candidates[:limit],errors
def curl_probe(proxy_url,url,accepted,timeout):
 cmd=["curl","-sS","-L","--connect-timeout","5","--max-time",str(timeout),"-o",os.devnull,"-w","%{http_code}","-x",proxy_url,url]
 try:
  result=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout+3)
  value=result.stdout.strip(); status=int(value) if value.isdigit() else 0
  ok=result.returncode==0 and status in accepted
  reason="pass" if ok else (f"http_{status}" if status else (result.stderr.strip()[-240:] or f"curl_exit_{result.returncode}"))
  return {"ok":ok,"status":status,"reason":reason}
 except subprocess.TimeoutExpired:return {"ok":False,"status":0,"reason":"timeout"}
 except Exception as exc:return {"ok":False,"status":0,"reason":str(exc)[:240]}
def probe_one(candidate,mihomo,work_dir,port,timeout):
 config_path=work_dir/"probe.yaml"; log_path=work_dir/"mihomo.log"
 proxy=dict(candidate["proxy"]); proxy["name"]="candidate"
 config_path.write_text(yaml.safe_dump(build_config(proxy,port,"error"),allow_unicode=True,sort_keys=False),encoding="utf-8")
 with log_path.open("wb") as log:
  process=subprocess.Popen([str(mihomo),"-d",str(work_dir),"-f",str(config_path)],stdout=log,stderr=subprocess.STDOUT)
  try:
   proxy_url=f"http://127.0.0.1:{port}"; ready=False; deadline=time.monotonic()+8
   while time.monotonic()<deadline:
    if process.poll() is not None:break
    check=subprocess.run(["curl","-sS","--max-time","2","-x",proxy_url,"-o",os.devnull,"-w","%{http_code}","https://www.google.com/generate_204"],capture_output=True,text=True)
    if check.returncode==0 and check.stdout.strip() in ("204","200","301","302"):
     ready=True;break
    time.sleep(.5)
   if not ready:
    try:tail=log_path.read_text(encoding="utf-8",errors="replace")[-500:]
    except Exception:tail=""
    return {name:{"ok":False,"status":0,"reason":"mihomo_start_failed"} for name,_,_ in APP_PROBES}
   return {name:curl_probe(proxy_url,url,accepted,timeout) for name,url,accepted in APP_PROBES}
  finally:
   if process.poll() is None:
    process.terminate()
    try:process.wait(timeout=3)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
def update_state(state,candidate,results,today):
 nodes=state.setdefault("nodes",{}); old=nodes.get(candidate["id"],{})
 passed=bool(results) and all(item.get("ok") is True for item in results.values())
 previous_date=old.get("last_test_date"); previous_streak=int(old.get("pass_streak",0) or 0)
 if passed:
  if previous_date==today.isoformat():streak=max(1,previous_streak)
  elif previous_date:
   try:gap=(today-dt.date.fromisoformat(previous_date)).days
   except ValueError:gap=99
   streak=previous_streak+1 if gap==1 else 1
  else:streak=1
  status="formal" if streak>=int(state.get("required_consecutive_days",3)) else "provisional"
 else:streak=0;status="rejected"
 nodes[candidate["id"]]={"country":candidate["country"],"protocol":candidate["protocol"],"name":candidate["name"],"status":status,"pass_streak":streak,"last_test_date":today.isoformat(),"last_test_at":utc_now().isoformat(),"app_results":results}
 return status,streak
def make_profile(proxies):
 names=[p["name"] for p in proxies]
 group={"name":"Proxy","type":"select","proxies":names+["DIRECT"]} if names else {"name":"Proxy","type":"select","proxies":["DIRECT"]}
 return {"mixed-port":7890,"allow-lan":False,"mode":"rule","log-level":"warning","ipv6":False,"proxies":proxies,"proxy-groups":[group],"rules":["MATCH,Proxy"] if names else ["MATCH,DIRECT"]}
def write_profile(path,proxies):
 path.write_text(yaml.safe_dump(make_profile(proxies),allow_unicode=True,sort_keys=False),encoding="utf-8")
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--input",default="sub/high_quality_nodes.txt");parser.add_argument("--state",default="state/cloud_robot_state.json")
 parser.add_argument("--formal-yaml",default="test_nodes.yaml");parser.add_argument("--provisional-yaml",default="test_nodes_provisional.yaml")
 parser.add_argument("--formal-uris",default="test_nodes.txt");parser.add_argument("--provisional-uris",default="test_nodes_provisional.txt")
 parser.add_argument("--report",default="cloud_robot_report.json");parser.add_argument("--mihomo",default="./mihomo")
 parser.add_argument("--max-candidates",type=int,default=20);parser.add_argument("--required-days",type=int,default=3)
 parser.add_argument("--timeout",type=int,default=10);parser.add_argument("--port",type=int,default=17890)
 args=parser.parse_args()
 input_path=Path(args.input)
 if not input_path.is_file() or not input_path.stat().st_size:raise SystemExit("Candidate input missing or empty; refusing to publish.")
 mihomo=Path(args.mihomo).resolve()
 if not mihomo.is_file():raise SystemExit(f"Mihomo binary not found: {mihomo}")
 candidates,parse_errors=read_candidates(input_path,args.max_candidates)
 if not candidates:raise SystemExit("No supported candidates parsed; refusing to publish.")
 state_path=Path(args.state);state_path.parent.mkdir(parents=True,exist_ok=True)
 state=json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"schema_version":1,"nodes":{}}
 if not isinstance(state,dict) or not isinstance(state.get("nodes",{}),dict):raise SystemExit("State file schema invalid; refusing to overwrite it.")
 state["schema_version"]=1;state["required_consecutive_days"]=args.required_days
 today=utc_date();formal=[];provisional=[];rejected=[];detail=[]
 with tempfile.TemporaryDirectory(prefix="smartsub-robot-") as temp:
  base=Path(temp)
  for index,candidate in enumerate(candidates):
   work=base/f"node-{index}";work.mkdir()
   results=probe_one(candidate,mihomo,work,args.port+index,args.timeout)
   status,streak=update_state(state,candidate,results,today)
   if status in ("formal","provisional"):
    proxy=dict(candidate["proxy"]);proxy["name"]=candidate["name"]
    (formal if status=="formal" else provisional).append((candidate,proxy))
   else:rejected.append(candidate)
   detail.append({"id":candidate["id"],"country":candidate["country"],"protocol":candidate["protocol"],"status":status,"pass_streak":streak,"app_results":results})
   print(f"[{index+1}/{len(candidates)}] {candidate['country']} {candidate['protocol']} -> {status} (streak={streak})")
 cutoff=today-dt.timedelta(days=30)
 for node_id,record in list(state["nodes"].items()):
  try:
   if dt.date.fromisoformat(record.get("last_test_date","1970-01-01"))<cutoff:del state["nodes"][node_id]
  except Exception:del state["nodes"][node_id]
 write_profile(Path(args.formal_yaml),[p for _,p in formal]);write_profile(Path(args.provisional_yaml),[p for _,p in provisional])
 Path(args.formal_uris).write_text("".join(c["uri"]+"\n" for c,_ in formal),encoding="utf-8")
 Path(args.provisional_uris).write_text("".join(c["uri"]+"\n" for c,_ in provisional),encoding="utf-8")
 state_path.write_text(json.dumps(state,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 report={"generated_at":utc_now().isoformat(),"policy":{"required_consecutive_days":args.required_days,"apps":[name for name,_,_ in APP_PROBES],"max_candidates_per_run":args.max_candidates},"summary":{"candidates_tested":len(candidates),"formal":len(formal),"provisional":len(provisional),"rejected":len(rejected),"parse_errors":len(parse_errors)},"results":detail,"parse_errors":parse_errors[:100]}
 Path(args.report).write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 print(json.dumps(report["summary"],ensure_ascii=False));return 0
if __name__=="__main__":raise SystemExit(main())
