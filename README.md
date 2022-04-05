# Malwasm
## Introduction
Malwasm is a command-line tool that detects the usage of WASM in websites and performs analysis to determine if the WASM files contain any malicious functions.

## Requirements
- Python 3
- Google Chrome 

## Command-Line Usage
### Installation

```bash
git clone https://github.com/Lyc4on/Malwasm.git
pip install -r requirements.txt # Recommended to use pyenv

# Set up chrome driver for Selenium
sudo apt-get install -y curl unzip xvfb libxi6 libgconf-2-4 fonts-liberation
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb
```

### Usage
Run Malwasm using **wasmanalyzer.py**:

```bash
# Scrape URL for wasm resources
python3 wasmanalyzer -u https://example.com

# Disassemble wasm binary to generate _dis.txt & _dis.wat
# _dis.wat - pseudo .wat file
# _dis.txt - contains CFG dictionary data, Module semantic profile, Functions' profile
python3 wasmanalyzer -d -f cryptonight.wasm

# Generate _rule.json rule file for analysis
python3 wasmanalyzer -gr -f cryptonight.wasm

# Deep analysis [-a 2] (Semantic Profiling) of game.wasm based on cryptonight_rule.json 
python3 wasmanalyzer -a 2 -f game.wasm -r cryptonight_rule.json

# Insert cfg, dfg, cg

# Insert yara
```


```
Options:
    -u          url of website to scrape wasm binaries & save in Temp folder
    -f          specify .wasm file to analyze/generate json rule
    -gr         generate json rule of -f .wasm input & save _rule.json in Output folder
    -d          disassemble .wasm & output _dis.txt, _dis.wat & save in Output folder
    -a          analyze -f .wasm based on -r rule.json & save _analysis.txt in Output folder
                -a [1, 2] - default=1, 1 = Quick Analysis, 2 = Deep Analysis
                Quick Analysis based on function's total instructions/block count
                Deep Analysis based on function's semantic profiling
    -r          specify .json rule for analysis
    -fn         <Insert description>
    -vt         <Insert description>
    -y          <Insert description>
    -cg         <Insert description>
    -cfg        <Insert description>
    -dfg        <Insert description>
```