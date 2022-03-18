# Malwasm
## Introduction
Malwasm is a command-line tool that detects the usage of WASM in websites and performs analysis to determine if the WASM files contain any malicious functions.

## Requirements
- Python 3
- Windows Environment

## Command-Line Usage
### Installation

```bash
git clone https://github.com/Lyc4on/Malwasm.git
pip install -r requirements.txt
```

### Running the Tool
Run Malwasm using **malwasm_detection.py**
```bash
# -u : URL of the website
python malwasm_detection.py -u https://sepiropht.github.io/tic-tac-toe-wasm/
```