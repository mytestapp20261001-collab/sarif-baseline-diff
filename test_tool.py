import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("local_tool", HERE / "tool.py")
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)

class Tests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(HERE/'tool.py'), *map(str,args)], capture_output=True, text=True)
    def codes(self, *args):
        return [item['code'] for item in tool.audit(*args)['findings']]
    def test_cli_bad_args(self):
        result = self.cli('--unknown')
        self.assertEqual(result.returncode, 2); self.assertEqual(json.loads(result.stdout)['status'], 'error')
    def test_read_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'big'; path.write_text(' '*(tool.MAX_BYTES+1))
            with self.assertRaises(tool.BadInput): tool.read_text(path)
    def good(self): return json.loads((HERE/'examples/baseline.json').read_text())
    def test_pass(self): self.assertEqual(tool.audit(self.good(), self.good())['status'], 'pass')
    def test_findings(self):
        codes = self.codes(self.good(),json.loads((HERE/'examples/fail.json').read_text()))
        self.assertIn('changed_result', codes); self.assertIn('added_result', codes)
    def test_cli_examples(self):
        for name, expected in [('pass',0),('fail',1)]:
            result=self.cli(HERE/'examples/baseline.json',HERE/f'examples/{name}.json')
            self.assertEqual(result.returncode,expected,result.stdout+result.stderr); json.loads(result.stdout)
    def test_removed(self):
        data=self.good(); data['runs'][0]['results']=[]
        self.assertIn('removed_result',self.codes(self.good(),data))
    def test_fingerprint_matches_moved_location(self):
        data=self.good(); data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']=9
        self.assertEqual(self.codes(self.good(),data),['changed_result'])
    def test_location_fallback(self):
        data=self.good(); del data['runs'][0]['results'][0]['fingerprints']
        self.assertEqual(tool.audit(data,data)['status'],'pass')
    def test_duplicate(self):
        data=self.good(); data['runs'][0]['results']*=2
        self.assertIn('duplicate_result_identity',self.codes(data,data))
    def test_unknown_version(self):
        data=self.good(); data['version']='1.0.0'
        with self.assertRaises(tool.BadInput): tool.audit(data,data)
    def test_missing_results(self):
        data=self.good(); del data['runs'][0]['results']
        with self.assertRaises(tool.BadInput): tool.audit(data,data)
    def test_missing_identity(self):
        data=self.good(); result=data['runs'][0]['results'][0]; del result['fingerprints']; del result['locations']
        with self.assertRaises(tool.BadInput): tool.audit(data,data)
    def test_rule_index_only_rejected(self):
        data=self.good(); del data['runs'][0]['results'][0]['ruleId']
        with self.assertRaises(tool.BadInput): tool.audit(data,data)
    def test_zero_line_rejected(self):
        data=self.good(); data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']=0
        with self.assertRaises(tool.BadInput): tool.audit(data,data)
    def test_private_messages_not_echoed(self):
        data=self.good(); data['runs'][0]['results'][0]['message']['text']='synthetic-secret-unique'
        self.assertNotIn('synthetic-secret-unique',json.dumps(tool.audit(self.good(),data)))
    def test_json_malformed_cli(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.json'
            for text in ['{','{"x":1,"x":2}','{"x":1e999}']:
                path.write_text(text); result=self.cli(path,path)
                self.assertEqual(result.returncode,2); json.loads(result.stdout)
    def test_tool_scoping(self):
        data=self.good(); data['runs'][0]['tool']['driver']['name']='different'
        self.assertEqual(set(self.codes(self.good(),data)),{'added_result','removed_result'})

if __name__ == "__main__": unittest.main()
