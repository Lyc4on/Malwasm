#! python3
import argparse
import os
import time
import urllib
import pyfiglet
import shutil
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from pathlib import Path


# Input URL of website as an argument
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--URL", help="URL of website", required=True)
args = parser.parse_args()

# Create folder Temp if it does not exist
Path("Temp").mkdir(parents=True, exist_ok=True)

# Setting Chrome options to hide the UI window
WINDOW_SIZE = "1920,1080"
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--window-size=%s" % WINDOW_SIZE)
chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
ser = Service("Resources\\executables\\chromedriver")

# Create banner
ascii_banner = pyfiglet.figlet_format("Malwasm")
print(ascii_banner)

print("Detecting WASM files...")
# Specify path to chromedriver and set specified options
driver = webdriver.Chrome(service=ser, options=chrome_options)
# Navigate to the specified URL
driver.get(args.URL)

# Get current working directory
current_working_directory = os.getcwd() + "\\Temp\\"
wasm_arr = []

# Wait for 5 seconds for the network requests to be made
time.sleep(5)
# Access requests via the `requests` attribute
print("WASM files found:")
for request in driver.requests:
    if request.response:
        if request.response.headers['Content-Type'] == 'application/wasm':
            print(request.url)
            filename = os.path.basename(request.url)
            full_filename = os.path.join(current_working_directory, filename)
            wasm_arr.append(full_filename)
            # Save the .wasm file into Temp folder
            urllib.request.urlretrieve(request.url, filename=full_filename)

# Close all windows and end driver's process
driver.quit()

if len(wasm_arr) == 0:
    print("No WASM files detected!")

print("\nPerforming analysis...")

# Clean up by deleting Temp folder
shutil.rmtree(current_working_directory)


# # Get output of all network requests made
# timings = driver.execute_script("return window.performance.getEntries();")
# print(len(timings))
# # Close all windows and end driver's process
# driver.quit()
#
# # Get current working directory
# current_working_directory = os.getcwd() + "\\Temp\\"
# print("WASM files found:")
# wasm_arr = []
# for i in range(len(timings)):
#     # Find .wasm files
#     if ".wasm" in timings[i]['name']:
#         print(timings[i]['name'])
#         filename = os.path.basename(timings[i]['name'])
#         full_filename = os.path.join(current_working_directory, filename)
#         wasm_arr.append(full_filename)
#         # Save the .wasm file into Temp folder
#         urllib.request.urlretrieve(timings[i]['name'], filename=full_filename)
#
