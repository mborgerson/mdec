#!/usr/bin/env python3
import unittest
import subprocess
import tempfile
import requests
import os


TEST_ROOT = os.path.abspath(os.path.dirname(__file__))


class ServicesTest(unittest.TestCase):

	@staticmethod
	def _test_service(service_name: str, binary_path: str):
		print(f'Testing {service_name}')
		with open(binary_path, 'rb') as f:
			r = requests.post(f'http://127.0.0.1/{service_name}/decompile',
				              files={'file': f})
			if r.status_code != 200:
				r.raise_for_status()

	def test_all_services(self):
		with tempfile.TemporaryDirectory() as working_dir:
			src_path = os.path.join(TEST_ROOT, 'src', 'fib.c')
			bin_path = os.path.join(working_dir, 'fib')
			subprocess.run(['gcc', '-o', bin_path, src_path], check=True)
			for service_name in ['angr', 'r2dec', 'reko', 'retdec', 'snowman']:
				self._test_service(service_name, bin_path)


if __name__ == '__main__':
	unittest.main()
