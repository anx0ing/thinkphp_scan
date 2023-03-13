# coding:utf-8
import sys
import argparse
import datetime
import urllib
from datetime import date, timedelta
from rich.console import Console
import core.code_rprint as rprint
from core.thinkphp_payloads import start_thinkphp
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

targets = './targets.txt'
date = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))

def get_time():
  return datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

if __name__=='__main__':

  print('''
  ░▀█▀░█░█░▀█▀░█▀█░█░█░█▀█░█░█░█▀█░░░░░█▀▀░█▀▀░█▀█░█▀█
  ░░█░░█▀█░░█░░█░█░█▀▄░█▀▀░█▀█░█▀▀░░░░░▀▀█░█░░░█▀█░█░█
  ░░▀░░▀░▀░▀▀▀░▀░▀░▀░▀░▀░░░▀░▀░▀░░░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀░▀
  ''')

  parser = argparse.ArgumentParser(description="Thinkphp漏洞扫描")
  parser.add_argument('-url','--url', type=str, help="target url")
  parser.add_argument('-file','--file', type=str, help="targets file path")
  args = parser.parse_args()


  try:
    if '-url' in sys.argv:
      rprint.info(get_time(), 'Thinkphp漏洞检测')
      start_thinkphp(args.url)
      rprint.info(get_time(), 'Thinkphp漏洞检测结束')
    elif '-file' in sys.argv:
      f = open(args.file,'r')
      rprint.info(get_time(), 'Thinkphp漏洞检测')
      for i in f:
        start_thinkphp(i)
      rprint.info(get_time(), 'Thinkphp漏洞检测结束')
    else:
      parser.print_help()
  except:
    pass


