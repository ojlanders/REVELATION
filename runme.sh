#!/bin/sh
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "Updating package lists..."
apt update

echo "Installing required packages..."
apt install -y python3-pip liblzo2-dev lz4 python3-venv git

echo "Creating a Python virtual environment..."
python3 -m venv myenv

. myenv/bin/activate

echo "Installing Python packages..."
pip install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df
pip install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
pip install --upgrade pyelftools

echo "Running revelation..."
python3 revelation.py /boot/vmlinuz-$(uname -r) --overwrite

deactivate

echo "Done."

