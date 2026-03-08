import urllib.request
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
url = "https://raw.githubusercontent.com/jinx-y/CIC-IDS-2017/master/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

print("Downloading dataset...")
try:
    urllib.request.urlretrieve(url, "cicids2017_sample.csv")
    print("Downloaded successfully.")
except Exception as e:
    print(f"Error: {e}")
