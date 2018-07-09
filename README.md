# [VirusTotal Public API] Maltego Local Transforms
Maltego Local Transform to use VirusTotal Public API - https://www.virustotal.com/en/documentation/public-api/

# Prerequisites
- VirusTotal Private API access
- Python 2.7.x + requests, json, random module

# 必要なもの
- VirusTotal Private APIのアクセス権
- Python 2.7.x + requests, json, random モジュール

# Setup
- Edit VTPub.py and set "apikey" variable with your API key.  
- Put VTPub.py and MaltegoTransform.py into your working directory. (e.g. C:\Maltego\Transforms\VirusTotal_Public)  
- Open VTPub.mtz to import Maltego configuration.  
- The current configuration uses the following directories, so you may have to change them according to your environment. (Maltego -> Transforms -> Transform Manager)  

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal_Public

# セットアップ
- VTPub.py の中で、\<Your API Key\> の箇所に自分の API key を記載してください。複数の API key を持っている場合は、クォータを増やすために複数記載することもできます。
- VTPub.py と MaltegoTransform.py を、このTransform用に作ったディレクトリに置いてください。（例： C:\Maltego\Transforms\VirusTotal_Public）
- VTPub.mtz を開いて、Maltegoの設定をインポートしてください。
- mtzファイルに含まれる設定では、下記のディレクトリが指定されていますが、自分の環境に合わせて変更してください。（Maltego -> Transforms -> Transform Manager）

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal_Public

# Transforms
- domain_reports
- ip_reports
- url_reports
- file_reports
- file_rescan
- url_scan
- md5
- sha256
