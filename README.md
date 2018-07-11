# [VirusTotal Public API] Maltego Local Transforms
Maltego Local Transform to use VirusTotal Public API - https://www.virustotal.com/en/documentation/public-api/

# Prerequisites
- VirusTotal Private API access
- Python 2.7.x + requests, json, random module
- Python 3.6.x will probably work.

# 必要なもの
- VirusTotal Private APIのアクセス権
- Python 2.7.x + requests, json, random モジュール
- Python 3.6.x でもたぶん動作します。

# Setup
- Edit VTPub.py and set "apikey" variable with your API key.  
- Put all python files into your working directory. (e.g. C:\Maltego\Transforms\VirusTotal_Public)  
- Open VTPub.mtz to import Maltego configuration.  
- The current configuration uses the following directories, so you may have to change them according to your environment. (Maltego -> Transforms -> Transform Manager)  

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal_Public

# セットアップ
- VTPub.py の中で、\<Your API Key\> の箇所に自分の API key を記載してください。複数の API key を持っている場合は、クォータを増やすために複数記載することもできます。
- 全てのPythonファイルを、このTransform用に作ったディレクトリに置いてください。（例： C:\Maltego\Transforms\VirusTotal_Public）
- VTPub.mtz を開いて、Maltegoの設定をインポートしてください。
- mtzファイルに含まれる設定では、下記のディレクトリが指定されていますが、自分の環境に合わせて変更してください。（Maltego -> Transforms -> Transform Manager）

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal_Public

# Transforms
- [VTPub] domain_reports
![vtpub-domain](https://user-images.githubusercontent.com/16297449/42553876-9d874676-851d-11e8-96dc-7310af19c0c3.png)
- [VTPub] ip_reports
![vtpub-ip](https://user-images.githubusercontent.com/16297449/42553927-e4149f58-851d-11e8-8da9-b9f016fca3ba.png)
- [VTPub] url_reports

- [VTPub] file_reports

- [VTPub] file_rescan

- [VTPub] url_scan

- [VTPub] md5

- [VTPub] sha256
