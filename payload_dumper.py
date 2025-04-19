#!/usr/bin/env python3
import struct
import hashlib
import bz2
import sys
import argparse
import bsdiff4
import io
import os
import brotli
import zipfile
import zstandard
import fsspec
import urllib.parse
from pathlib import Path
import concurrent.futures
from functools import partial

try:
    import lzma
except ImportError:
    from backports import lzma

import update_metadata_pb2 as um

BSDF2_MAGIC = b'BSDF2'

flatten = lambda l: [item for sublist in l for item in sublist]

def u32(x):
    return struct.unpack('>I', x)[0]

def u64(x):
    return struct.unpack('>Q', x)[0]

def bsdf2_decompress(alg, data):
    if alg == 0:
        return data
    elif alg == 1:
        return bz2.decompress(data)
    elif alg == 2:
        return brotli.decompress(data)

# Adapted from bsdiff4.read_patch
def bsdf2_read_patch(fi):
    """read a bsdiff/BSDF2-format patch from stream 'fi'
    """
    magic = fi.read(8)
    if magic == bsdiff4.format.MAGIC:
        # bsdiff4 uses bzip2 (algorithm 1)
        alg_control = alg_diff = alg_extra = 1
    elif magic[:5] == BSDF2_MAGIC:
        alg_control = magic[5]
        alg_diff = magic[6]
        alg_extra = magic[7]
    else:
        raise ValueError("incorrect magic bsdiff/BSDF2 header")

    # length headers
    len_control = bsdiff4.core.decode_int64(fi.read(8))
    len_diff = bsdiff4.core.decode_int64(fi.read(8))
    len_dst = bsdiff4.core.decode_int64(fi.read(8))

    # read the control header
    bcontrol = bsdf2_decompress(alg_control, fi.read(len_control))
    tcontrol = [(bsdiff4.core.decode_int64(bcontrol[i:i + 8]),
                 bsdiff4.core.decode_int64(bcontrol[i + 8:i + 16]),
                 bsdiff4.core.decode_int64(bcontrol[i + 16:i + 24]))
                for i in range(0, len(bcontrol), 24)]

    # read the diff and extra blocks
    bdiff = bsdf2_decompress(alg_diff, fi.read(len_diff))
    bextra = bsdf2_decompress(alg_extra, fi.read())
    return len_dst, tcontrol, bdiff, bextra

def verify_contiguous(exts):
    blocks = 0

    for ext in exts:
        if ext.start_block != blocks:
            return False

        blocks += ext.num_blocks

    return True

def open_payload_file(file_path):
    """
    Opens a payload file, whether it's a local file, a remote file,
    or inside a zip archive (local or remote).
    
    Returns a file-like object pointing to the payload.bin content.
    """
    # Check if the file is a URL
    is_url = file_path.startswith(('http://', 'https://', 's3://', 'gs://'))
    
    if is_url:
        # Handle remote file
        protocol = urllib.parse.urlparse(file_path).scheme
        fs = fsspec.filesystem(protocol)
        
        # Open the remote file
        remote_file = fs.open(file_path)
        
        # Check if it's a zip file
        if zipfile.is_zipfile(remote_file):
            # Reset the file pointer
            remote_file.seek(0)
            
            # Open as a zip file and extract payload.bin
            with zipfile.ZipFile(remote_file) as zf:
                if "payload.bin" in zf.namelist():
                    return zf.open("payload.bin")
                else:
                    raise ValueError("payload.bin not found in zip file")
        else:
            # Not a zip file, use as is
            return remote_file
    else:
        # Local file
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as zf:
                if "payload.bin" in zf.namelist():
                    return zf.open("payload.bin")
                else:
                    raise ValueError("payload.bin not found in zip file")
        else:
            # Local file, not a zip
            return open(file_path, 'rb')

def data_for_op(op, payload_file, out_file, old_file, data_offset, block_size):
    payload_file.seek(data_offset + op.data_offset)
    data = payload_file.read(op.data_length)

    if op.data_sha256_hash:
        assert hashlib.sha256(data).digest() == op.data_sha256_hash, 'operation data hash mismatch'

    if op.type == op.REPLACE_XZ:
        dec = lzma.LZMADecompressor()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.ZSTD:
        dec = zstandard.ZstdDecompressor().decompressobj()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.REPLACE_BZ:
        dec = bz2.BZ2Decompressor()
        data = dec.decompress(data)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.REPLACE:
        out_file.seek(op.dst_extents[0].start_block*block_size)
        out_file.write(data)
    elif op.type == op.SOURCE_COPY:
        if not old_file:
            print("SOURCE_COPY supported only for differential OTA")
            sys.exit(-2)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        for ext in op.src_extents:
            old_file.seek(ext.start_block*block_size)
            data = old_file.read(ext.num_blocks*block_size)
            out_file.write(data)
    elif op.type in (op.SOURCE_BSDIFF, op.BROTLI_BSDIFF):
        if not old_file:
            print("BSDIFF supported only for differential OTA")
            sys.exit(-3)
        out_file.seek(op.dst_extents[0].start_block*block_size)
        tmp_buff = io.BytesIO()
        for ext in op.src_extents:
            old_file.seek(ext.start_block*block_size)
            old_data = old_file.read(ext.num_blocks*block_size)
            tmp_buff.write(old_data)
        tmp_buff.seek(0)
        old_data = tmp_buff.read()
        tmp_buff.seek(0)
        tmp_buff.write(bsdiff4.core.patch(old_data, *bsdf2_read_patch(io.BytesIO(data))))
        n = 0
        tmp_buff.seek(0)
        for ext in op.dst_extents:
            tmp_buff.seek(n*block_size)
            n += ext.num_blocks
            data = tmp_buff.read(ext.num_blocks*block_size)
            out_file.seek(ext.start_block*block_size)
            out_file.write(data)
    elif op.type == op.ZERO:
        for ext in op.dst_extents:
            out_file.seek(ext.start_block*block_size)
            out_file.write(b'\x00' * ext.num_blocks*block_size)
    else:
        print(f"Unsupported type = {op.type}")
        sys.exit(-1)

    return data

def dump_part(part, payload_path, data_offset, block_size, out_dir, old_dir=None, use_diff=False):
    print(f"Processing {part.partition_name} partition...")
    
    # Ensure output directory exists
    Path(out_dir).mkdir(exist_ok=True)
    
    # We need to open a new file handle for each partition in parallel processing
    with open_payload_file(payload_path) as payload_file:
        out_file = open(f'{out_dir}/{part.partition_name}.img', 'wb')
        
        if use_diff:
            old_file_path = f'{old_dir}/{part.partition_name}.img'
            if os.path.exists(old_file_path):
                old_file = open(old_file_path, 'rb')
            else:
                print(f"Warning: Original image {old_file_path} not found for differential OTA")
                old_file = None
        else:
            old_file = None

        operation_count = len(part.operations)
        completed = 0
        
        for op in part.operations:
            data = data_for_op(op, payload_file, out_file, old_file, data_offset, block_size)
            completed += 1
            if completed % 10 == 0 or completed == operation_count:
                print(f"  {part.partition_name}: {completed}/{operation_count} operations completed")
        
        out_file.close()
        if old_file:
            old_file.close()
    
    print(f"Finished processing {part.partition_name}")
    return part.partition_name

def main():
    parser = argparse.ArgumentParser(description='OTA payload dumper')
    parser.add_argument('payload_path', type=str,
                        help='payload file path or URL (can be a zip file)')
    parser.add_argument('--out', default='output',
                        help='output directory (default: output)')
    parser.add_argument('--diff', action='store_true',
                        help='extract differential OTA, you need put original images to old dir')
    parser.add_argument('--old', default='old',
                        help='directory with original images for differential OTA (default: old)')
    parser.add_argument('--images', default="",
                        help='comma-separated list of images to extract (default: all)')
    parser.add_argument('--list', action='store_true',
                        help='list all available partitions in the payload without extracting')
    parser.add_argument('--workers', type=int, default=os.cpu_count(),
                        help='number of worker processes (default: number of CPU cores)')
    args = parser.parse_args()

    # Ensure output directory exists
    if not os.path.exists(args.out) and not args.list:
        os.makedirs(args.out)

    # Open the payload file to extract metadata
    with open_payload_file(args.payload_path) as payload_file:
        # Read and verify the magic header
        magic = payload_file.read(4)
        assert magic == b'CrAU', "Invalid magic header, not an OTA payload"

        file_format_version = u64(payload_file.read(8))
        assert file_format_version == 2, f"Unsupported file format version: {file_format_version}"

        manifest_size = u64(payload_file.read(8))

        metadata_signature_size = 0
        if file_format_version > 1:
            metadata_signature_size = u32(payload_file.read(4))

        manifest = payload_file.read(manifest_size)
        metadata_signature = payload_file.read(metadata_signature_size)

        data_offset = payload_file.tell()

        dam = um.DeltaArchiveManifest()
        dam.ParseFromString(manifest)
        block_size = dam.block_size

        # If --list is specified, just list the partitions and exit
        if args.list:
            print("Available partitions in payload:")
            for i, part in enumerate(dam.partitions):
                print(f"  {i+1}. {part.partition_name}")
            return

        # Select partitions to process
        if args.images == "":
            partitions_to_process = dam.partitions
        else:
            images = args.images.split(",")
            partitions_to_process = []
            for image in images:
                partition = [part for part in dam.partitions if part.partition_name == image]
                if partition:
                    partitions_to_process.append(partition[0])
                else:
                    sys.stderr.write(f"Partition {image} not found in payload!\n")
        
        # Process partitions in parallel
        print(f"Starting extraction with {args.workers} worker processes")
        with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
            # Create a partial function with the common arguments
            dump_part_partial = partial(
                dump_part,
                payload_path=args.payload_path,
                data_offset=data_offset,
                block_size=block_size,
                out_dir=args.out,
                old_dir=args.old if args.diff else None,
                use_diff=args.diff
            )
            
            # Submit all partitions for processing
            futures = {executor.submit(dump_part_partial, part): part.partition_name 
                      for part in partitions_to_process}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                partition_name = futures[future]
                try:
                    result = future.result()
                    print(f"Successfully extracted {result}")
                except Exception as exc:
                    print(f"{partition_name} generated an exception: {exc}")

if __name__ == "__main__":
    main()
