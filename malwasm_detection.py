#!/usr/bin/env python3
import argparse
import os
import pyfiglet
import shutil
import time
import urllib
from pathlib import Path
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


# Input URL of website as an argument
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--URL", help="URL of website", required=True)
args = parser.parse_args()

# Check to ensure input is a valid URL
if args.URL.startswith('http://') or args.URL.startswith('https://'):
    pass
else:
    raise ValueError("Please enter a valid URL!")

# Create Temp folder if it does not exist
Path("Temp").mkdir(parents=True, exist_ok=True)

# Disable logging in WebDriverManager
os.environ['WDM_LOG'] = '0'

# Set Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
ser = Service(ChromeDriverManager().install())

# Create banner
ascii_banner = pyfiglet.figlet_format("Malwasm")
print(ascii_banner)

# Get absolute path to Temp directory
working_directory = os.getcwd() + os.sep + "Temp" + os.sep
wasm_arr = []

print("[+] Detecting WASM files in " + args.URL)
# Create webdriver instance with specified options
driver = webdriver.Chrome(service=ser, options=chrome_options)
# Navigate to the specified URL
driver.get(args.URL)
# Wait for 5 seconds for the network requests to be made
time.sleep(5)

# Access requests via the 'requests' attribute
for request in driver.requests:
    if request.response and request.response.headers['Content-Type'] == 'application/wasm':
        wasm_arr.append(request.url)
        filename = os.path.basename(request.url)
        full_filename = os.path.join(working_directory, filename)
        # Save the .wasm file into Temp folder
        urllib.request.urlretrieve(request.url, filename=full_filename)
        break

# Close all windows and end driver's process
driver.quit()

print("[+] Detection Results: ")
# Print out all WASM files that were detected
if len(wasm_arr) == 0:
    print("No WASM files detected!")
else:
    print("Number of WASM files detected: " + str(len(wasm_arr)))
    print("WASM files detected:")
    for wasm_file in wasm_arr:
        print("- " + wasm_file)

    # Perform analysis
    print("\n[+] Performing analysis")
    print("[+] Analysis Results: ")

# Clean up by deleting Temp folder
print("\n[+] Cleaning up")
# shutil.rmtree(working_directory)
