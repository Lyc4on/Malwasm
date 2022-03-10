from bs4 import BeautifulSoup as bs
import requests
from urllib.parse import urljoin

# URL of the web page you want to extract
url = "https://wasmbyexample.dev/examples/strings/strings.c.en-us.html#"

# initialize a session
session = requests.Session()

# get the HTML content
html = session.get(url).content
# parse HTML using beautiful soup
soup = bs(html, "html.parser")

for script in soup.find_all("script"):
    print(script)
    if "fetch(*.wasm)" in script.text:
        print(script.text)
        print(script.text.split("fetch(")[1].split(")")[0])
        print(urljoin(url, script.text.split("fetch(")[1].split(")")[0]))
        print(session.get(urljoin(url, script.text.split("fetch(")[1].split(")")[0])).content)
    
