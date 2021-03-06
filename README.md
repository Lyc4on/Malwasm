# Malwasm
## Introduction
Malwasm is a command-line tool that detects the usage of WASM in websites and performs analysis to determine if the WASM files contain any malicious functions.

## Requirements
- Python 3
- Google Chrome 

## Installation

```bash
git clone https://github.com/Lyc4on/Malwasm.git
pip install -r requirements.txt # Recommended to use pyenv

# Set up chrome driver for Selenium
sudo apt-get install -y curl unzip xvfb libxi6 libgconf-2-4 fonts-liberation
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb
```

## System Architecture
![](src/System_Architecture.png)

## Usage
Run Malwasm using **wasmanalyzer.py**:

```bash
# Scrape URL for wasm resources
python3 wasmanalyzer.py -u https://example.com

# Disassemble wasm binary to generate _dis.txt & _dis.wat
# _dis.wat - pseudo .wat file
# _dis.txt - contains CFG dictionary data, Module semantic profile, Functions' profile
python3 wasmanalyzer.py -d -f cryptonight.wasm

# Generate _rule.json rule file for analysis
python3 wasmanalyzer.py -gr -f cryptonight.wasm

# Deep analysis [-a 2] (Semantic Profiling) of game.wasm based on cryptonight_rule.json 
python3 wasmanalyzer.py -a 2 -f game.wasm -r cryptonight_rule.json

# Gnerate Call Graph from wasm file 
python3 wasmanalyzer.py -cg -f cryptonight.wasm 

# Gnerate Control Flow Graph from wasm file 
python3 wasmanalyzer.py -cfg -fn <function name> -f cryptonight.wasm 

# Gnerate Data Flow Graph from wasm file 
python3 wasmanalyzer.py -dfg -fn <function name> -f cryptonight.wasm 

# Run yara program against wasm file for malicious signature
# custom rules can be added to resources/yara_rules/ directory and the program will compile the rules
python3 wasmanalyzer.py -y -f cryptonight.wasm 
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
    -fn         specify the function name for generation of the control flow and data flow graph
    -y          specify yara malware detection program to run
    -cg         generate call graph from specified wasm file
    -cfg        generate control flow graph from specified wasm file with the specified function name
    -dfg        generate data flow graph from specified wasm file with the specified function name
```

## Demo
https://user-images.githubusercontent.com/56181271/162015233-f190f4c3-54da-4c8a-ab30-740d80edea09.mp4

## Sample Usage
Scrape wasm file from URL
![](src/01_url.png)

Disassebmle wasm file
![](src/02_dis.png)

Generate semantic profile rule from wasm file
![](src/03_gr.png)

Quick analysis of wasm file against generated rule
![](src/04_a_1.png)

Deep analysis of wasm file against generated rule
![](src/05_a_2.png)

Generate Call Graph of wasm file
![](src/06_cg.png)

Generate Control Flow Graph of specified function in wasm file
![](src/07_cfg.png)

Generate Data Flow Graph of specified function in wasm file
![](src/08_dfg.png)

Scan wasm file againsts YARA rule
![](src/09_yara.png)

