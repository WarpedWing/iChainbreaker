# iChainbreaker

iChainbreaker is just PoC code for analyzing Local Items (iCloud) Keychain. This project will be merged with Chainbreaker.

**Python 3 Fork**: This fork has been upgraded from Python 2 to Python 3.14+.

## Installation

### Prerequisites

- Python 3.14 or later
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Quick Install with uv (Recommended)

```shell
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/WarpedWing/iChainbreaker
cd iChainbreaker

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

### Alternative: Install with pip

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## How to use

```shell
python iChainbreaker.py -h
```

```
usage: iChainbreaker.py [-h] -p PATH [-k KEY] [-x EXPORTFILE] -v VERSION

Tool for iCloud Keychain Analysis by @n0fate

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  iCloud Keychain Path(~/Library/Keychains/[UUID]/)
  -k KEY, --key KEY     User Password (optional, will prompt if not provided)
  -x EXPORTFILE, --exportfile EXPORTFILE
                        Write a decrypted contents to SQLite file (optional)
  -v VERSION, --version VERSION
                        macOS version(ex. 10.13)
```

### Example

```shell
python iChainbreaker.py \
  -p ~/Library/Keychains/94C2D0C3-4F0C-4915-9ACE-2CFB4998EDA9/ \
  -v 10.15
```

You will be prompted for your user password if not provided via `-k`.

## Reference

Sogeti ESEC Lab, iPhone data protection in depth, HITB Amsterdam 2011.

## License

GPL v2
