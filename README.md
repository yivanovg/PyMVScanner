<h1 align="center">Welcome to PyVMScanner 👋</h1>
<p align="center">
  <img src="https://img.shields.io/npm/v/readme-md-generator.svg?orange=blue" />
  <img src="https://img.shields.io/badge/FAQ-PRESENT-brightgreen"/>
  <a href="https://www.npmjs.com/package/readme-md-generator">
    <img alt="downloads" src="https://img.shields.io/npm/dm/readme-md-generator.svg?color=blue" target="_blank" />
  </a>
  <a href="https://github.com/yivanovg/PyMVScanner/blob/master/LICENSE">
    <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-yellow.svg" target="_blank" />
  </a>
  <img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/requests">
  </p>
PYVMSCANNER is a web based python vulnerability scanner capable of discovering vulnerabilities and carrying out a number of different scans.

## Installation

Do not forget to activate your virtual enivronment first !!!

```python
python3 -m venv /path/to/new/virtual/environment
In Admin CMD
/path/to/new/virtual/environment/Scripts/activate.bat
```
And then proceed with install as normal when virtual-env is loaded.

The manual way:

```
git clone https://github.com/yivanovg/PyMVScanner
cd PyMVScanner
pip install -r PyMVScanner/requirements.txt
PyMVScanner.py --help
```
Or download the project as a zip and extract it on your local machine and then:

```
Open CMD Admin
cd PyMVScanner
pip install -r PyMVScanner/requirements.txt
PyMVScanner.py --help
```

## Features

  <li>
    SQL Scanner Error Based
  </li>
  <li>
    HTTP Security Header Check
  </li>
  <li>
    Cookies Security Flags Check
  </li>
  <li>
    SSL Redirect Check
  </li><li>
    SLL Support Check
  </li>
  <li>
    Admin Panel Finder
  </li>
  <li>
    Directory and FIle Discovery
  </li>
  <li>
    Host Lookup Via WHOIS and IPWHOIS
  </li>
  <li>
    URL TO IP Change
  </li>
  <li>
    IP TO URL Change
  </li>
  <li>
    PORT SCAN: [TCP] [TCP STEALTH] [UDP] [FIN]
  </li>
  
## Usage
Below is an image  of the program CLI and the Help Menu.

```python
PyMVScanner.py --help
```
<img width="1000" src="https://github.com/yivanovg/PyMVScanner/blob/master/data/scannerDemo.PNG" alt="cli output"/>
 
```python
PyMVScanner.py --help
PyMVScanner.py --portscan --url www.hackthissite.org --ports 20-500 --fsave False
PyMVScanner.py sqlscan --url www.hackthissite.org --fsave True
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/) PyMVScanner is built for authorized use only!!!
