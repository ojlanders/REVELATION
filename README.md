# Revelation

Revelation is a red team tool that patches the `nf_hook_slow` function in the Linux kernel to disable netfilter. This effectively renders packet filtering mechanisms like iptables and nftables useless, allowing all network traffic to bypass firewall rules once root access is obtained.

The tool includes an automated installation script (`runme.sh`) that sets up necessary dependencies and a Python virtual environment. The patching process involves extracting the kernel from a bzImage, applying a patch to the `nf_hook_slow` function, and repacking the kernel.

## How It Works

Revelation modifies the `nf_hook_slow` function in the Linux kernel, forcing it to always return `NF_ACCEPT` (1), which disables firewall filtering. Once the kernel is patched, iptables and nftables will appear to be running, but they will not be able to filter any traffic. The system will continue to accept all packets.

The tool works with kernels compressed using algorithms like xz and lz4. You can either overwrite the original bzImage with the patched version or save the modified kernel with a `.patched` extension for external deployment.

## Installation and Dependencies

Revelation requires a few key dependencies and tools to run, which are installed automatically by the `runme.sh` script. Here’s what you need to know:

- **Python 3.x** is required.
- **pyelftools** is used to parse ELF files.
- **vmlinux-to-elf** is used to extract kernel symbols and analyze the uncompressed kernel.
- Various compression utilities (`lz4`, `xz`, `gzip`, `bzip2`, etc.) are used based on the compression format of the kernel. You will need the correct compressor installed for the kernel image you are using.

### Installation Steps

1. Clone the repository:
   ```
   git clone http://github.com/ojlanders/REVELATION
   cd REVELATION
   ```

2. Run the installation script:
   ```
   sudo bash runme.sh
   ```

   The script will:
   - Install required packages (`python3-pip`, `liblzo2-dev`, `lz4`, `git`, etc.).
   - Set up a Python virtual environment.
   - Install the required Python packages, including `vmlinux-to-elf` and `pyelftools`.

3. The script will automatically run `revelation.py` to patch the running kernel if root access is available. This step overwrites the current kernel with the patched version unless you specify otherwise.

## Usage Instructions

You can run Revelation either on the target system or on your own machine after extracting the target's kernel. Below are the steps for both approaches.

### On the Target System

1. Ensure you have root access on the target machine.
2. Run the `runme.sh` script to set up the environment and patch the kernel:
   ```
   sudo bash runme.sh
   ```

3. Reboot the machine after the patching process completes. The iptables/nftables system will now be disabled until the kernel is replaced or updated.

### On Your Own Machine

1. Extract the kernel image (`bzImage`) from the target machine:
   ```
   cp /boot/vmlinuz-$(uname -r) ./kernel_image
   ```

2. Patch the kernel:
   ```
   python3 revelation.py /path/to/kernel_image --overwrite
   ```

   You can omit `--overwrite` to save the patched kernel as a new file with a `.patched` extension.

3. Install the patched kernel on the target machine:
   ```
   sudo cp kernel_image.patched /boot/vmlinuz-$(uname -r)
   sudo reboot
   ```

## Commands Overview

- To patch a kernel and overwrite the existing bzImage:
  ```
  python3 revelation.py /path/to/bzImage --overwrite
  ```

- To patch a kernel without overwriting the bzImage (writes to `<original_name>.patched`):
  ```
  python3 revelation.py /path/to/bzImage
  ```

- To airgap the machine for testing (blocks all network access except for loopback):
  ```
  sudo ./airgap.sh
  ```

## Limitations and Considerations

- **Root access is required** to patch the kernel.
- The ctime on the patched kernel is not automatically restored in overwrite mode, which could raise suspicion if you’re trying to avoid detection. You may want to manually restore the file’s timestamps after patching by using timedatectl.
- Revelation has been **tested on x86_64** systems running Debian 12 with xz and lz4 compressed kernels. It should work on other Linux distributions and architectures, but you will need to make minor modifications.
