from requests_html import HTMLSession
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests

import logging
import os
from datetime import datetime
import json
from lxml.html import fromstring
import pdb

import ssl
import socket
import OpenSSL


class WebScraper:
    def metadata_extractor(self, url, **kwargs):
        if 'proxy' in kwargs.keys():
            response = requests.get(url, proxies=kwargs['proxy'], allow_redirects=kwargs['allow_redirects'])
        else:
            response = requests.get(url, allow_redirects=kwargs['allow_redirects'])
        data = {
            "header": response.headers,
            "text": response.text,
            "is_redirect": response.is_redirect,
            "status_code": response.status_code,
            "response_url": response.url
        }
        return data

    def html_scraper(self, url, **kwargs):
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36', 
            'Accept-Encoding': 'gzip, deflate', 
            'Accept': '*/*', 
            'Connection': 'keep-alive'
        }
        port = None
        proxy = {}
        if 'proxy' in kwargs.keys():
            if "https" in url:
                port = 443
                proxy["https"] = kwargs['proxy']
            else:
                port = 80
                proxy["http"] = kwargs['proxy']
            results = requests.get(url, proxies=proxy, allow_redirects=kwargs['allow_redirects'], headers=headers)
        else:
            results = requests.get(url, allow_redirects=kwargs['allow_redirects'], headers=headers)
        return results.text

    def selenium_scraper(self, url, **kwargs):
        chrome_options = Options()  
        chrome_options.add_argument("--headless")
        if 'proxy' in kwargs.keys():
            chrome_options.add_argument('--proxy-server={proxy}'.format(proxy=kwargs['proxy']))
        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.get(url)
        html = driver.page_source
        driver.quit()
        return html

    def get_certificate(self, host, port, timeout=360000):
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port))
        sock = context.wrap_socket(conn, server_hostname=host)
        sock.settimeout(timeout)
        try:
            der_cert = sock.getpeercert(True)
        finally:
            sock.close()
        return ssl.DER_cert_to_PEM_cert(der_cert)

    # def get_proxies():
    #     url = 'https://free-proxy-list.net/'
    #     response = requests.get(url)
    #     parser = fromstring(response.text)
    #     proxies = set()
    #     for i in parser.xpath('//tbody/tr')[:10]:
    #         if i.xpath('.//td[7][contains(text(),"yes")]'):
    #             #Grabbing IP and corresponding PORT
    #             proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
    #             proxies.add(proxy)
    #     return proxies
