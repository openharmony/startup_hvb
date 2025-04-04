#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
'''
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
'''

import binascii
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
import bisect
import shutil
import random


_params = {
    'partition':                 None,             \
    'partition_size':            0,                \
    'image':                     None,             \
    'verity_type':               'hash',           \
    'algorithm':                 'SHA256_RSA3072', \
    'userid':                    None,             \
    'rollback_location':         None,             \
    'rollback_index':            None,             \
    'salt':                      None,             \
    'pubkey':                    None,             \
    'privkey':                   None,             \
    'hash_algo':                 'SHA256',         \
    'block_size':                4096,             \
    'fec_num_roots':             0,                \
    'pubkey_num_per_ptn':        1,                \
    'padding_size':              None,             \
    'chain_partition':           [],               \
    'signing_helper_with_files': None,             \
    'calc_max_image_size':      'false',           \
    'output':                    None
}


VERITY_TYPE = {
    'make_hash_footer':      'hash',   \
    'make_hashtree_footer':  'hashtree'
}


class Algorithm(object):
    def __init__(self, sig_algo, hash_algo, bit_length, sig_bytes, hash_bytes, pubkey_bytes):
        self.sig_algo = sig_algo
        self.hash_algo = hash_algo
        self.bit_length = bit_length
        self.sig_bytes = sig_bytes
        self.hash_bytes = hash_bytes
        self.pubkey_bytes = pubkey_bytes


ALGORITHMS = {'SHA256_RSA3072': Algorithm(
        sig_algo=0,
        hash_algo='sha256',
        bit_length=3072,
        sig_bytes=384,
        hash_bytes=32,
        pubkey_bytes=8 + 2 * 3072 // 8
    ), \
    'SHA256_RSA4096': Algorithm(
        sig_algo=1,
        hash_algo='sha256',
        bit_length=4096,
        sig_bytes=512,
        hash_bytes=32,
        pubkey_bytes=8 + 2 * 4096 // 8
    ), \
    'SHA256_RSA2048': Algorithm(
        sig_algo=2,
        hash_algo='sha256',
        bit_length=2048,
        sig_bytes=256,
        hash_bytes=32,
        pubkey_bytes=8 + 2 * 2048 // 8
    ), \
    'SM2': Algorithm(
        sig_algo=3,
        hash_algo='SM3',
        bit_length=256,    # bit
        sig_bytes=64,
        hash_bytes=32,
        pubkey_bytes=64
    ) \
}

HASH_ALGORITHM = {
    'sha256' : 0,
    'sha128' : 1,
    'sha512' : 2,
    'SM3'    : 3
}


def round_to_multiple(num, size):
    remainder = num % size
    if remainder == 0:
        return num
    return num + size - remainder


def create_random_data(length=64):
    data = ''
    chars = '0123456789abcdef'
    len_chars = len(chars) - 1
    for i in range(length):
        data += chars[random.randint(0, len_chars)]
    return data


def encode_long(num_bits, value):
    ret = bytearray()
    for bit_pos in range(num_bits, 0, -8):
        octet = (value >> (bit_pos - 8)) & 0xff
        ret.extend(struct.pack('!B', octet))
    return ret


def decode_long(blob):
    ret = 0
    for b in bytearray(blob):
        ret *= 256
        ret += b
    return ret


def calc_hashtree_size(size, block_size, digest_size):
    level_offsets = []
    level_sizes = []

    treesize = 0
    levels = 0

    while size > block_size:
        blocknum = size // block_size
        level_size = round_to_multiple(blocknum * digest_size, block_size)
        level_sizes.append(level_size)
        treesize += level_size
        levels += 1
        size = level_size
    for i in range(levels):
        offset = 0
        for j in range(i + 1, levels):
            offset += level_sizes[j]
        level_offsets.append(offset)

    return level_offsets, treesize


def get_sm3_digest(handle):
    cmds = ['openssl', 'dgst', '-SM3', handle]
    p = subprocess.Popen(cmds, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (pout, perr) = p.communicate(timeout=10)
    retcode = p.wait()
    if retcode != 0:
        raise HvbError("Failed to calculate the hash using SM3.")
    return binascii.a2b_hex(pout.split(b'=')[-1].strip())


def get_sha256_digest(hash_algo, salt, content):
    hasher = hashlib.new(hash_algo, salt)
    hasher.update(content)
    return hasher.digest()


def generate_sha_hash_tree(image, image_size, block_size, hash_algo, salt, hash_level_offsets, tree_size):
    hash_ret = bytearray(tree_size)
    hash_src_offset = 0
    hash_src_size = image_size
    level_num = 0

    while hash_src_size > block_size:
        level_output_list = []
        remaining = hash_src_size
        while remaining > 0:
            hasher = hashlib.new(hash_algo, salt)
            if level_num == 0:
                begin = hash_src_offset + hash_src_size - remaining
                end = min(remaining, block_size)
                image.seek(begin)
                data = image.read(end)
            else:
                offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining
                data = hash_ret[offset : offset + block_size]
            hasher.update(data)

            remaining -= len(data)
            if len(data) < block_size:
                hasher.update(b'\0' * (block_size - len(data)))
            level_output_list.append(hasher.digest())

        level_output = b''.join(level_output_list)
        level_output_padding = round_to_multiple(len(level_output), block_size) - len(level_output)
        level_output += b'\0' * level_output_padding

        offset = hash_level_offsets[level_num]
        hash_ret[offset : offset + len(level_output)] = level_output

        hash_src_size = len(level_output)
        level_num += 1

    hasher = hashlib.new(hash_algo, salt)
    hasher.update(level_output)

    return hasher.digest(), bytes(hash_ret)


def generate_sm3_hash_tree(image, image_size, block_size, hash_level_offsets, tree_size):
    hash_ret = bytearray(tree_size)
    hash_src_offset = 0
    hash_src_size = image_size
    level_num = 0
    tmp = 'hash_{}.bin'.format(os.getpid())

    while hash_src_size > block_size:
        level_output_list = []
        remaining = hash_src_size
        while remaining > 0:
            hasher = b''
            if level_num == 0:
                begin = hash_src_offset + hash_src_size - remaining
                end = min(remaining, block_size)
                image.seek(begin)
                data = image.read(end)
            else:
                offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining
                data = hash_ret[offset : offset + block_size]
            hasher += data

            remaining -= len(data)
            if len(data) < block_size:
                hasher += b'\0' * (block_size - len(data))

            if os.path.exists(tmp):
                os.remove(tmp)

            fd = open(tmp, 'wb')
            fd.write(hasher)
            fd.close()

            dgst = get_sm3_digest(tmp)
            level_output_list.append(dgst)

        level_output = b''.join(level_output_list)
        level_output_padding = round_to_multiple(len(level_output), block_size) - len(level_output)
        level_output += b'\0' * level_output_padding

        offset = hash_level_offsets[level_num]
        hash_ret[offset : offset + len(level_output)] = level_output

        hash_src_size = len(level_output)
        level_num += 1

    if os.path.exists(tmp):
        os.remove(tmp)

    fd = open(tmp, 'wb')
    fd.write(level_output)
    fd.close()

    root_digest = get_sm3_digest(tmp)

    return root_digest, bytes(hash_ret)


class HvbFooter(object):
    FOOTERMAGIC = b'HVB' + b'\0' * 5
    FOOTER_FORMAT = ('8s'  # Magic
                     '4Q'  # Cert offset, Cert size, Image_size, Partition_size
                     '64s'  # Reserved
                     )

    def __init__(self, footer=None):
        self.foot = footer
        if self.foot:
            (self.magic, self.certoffset, self.certsize, self.imagesize,
             self.partition_size, _) = struct.unpack(self.FOOTER_FORMAT, footer)
            if self.magic != self.FOOTERMAGIC:
                raise HvbError('Given footer does not look like a HVB footer.')
        else:
            raise HvbError('Given footer is None.')

    def info_footer(self):
        msg = "[HVB footer]: \n"
        if self.foot:
            msg += "\tMaigc:                   {}\n".format((self.magic).decode())
            msg += "\tCert offset:             {} bytes\n".format(hex(self.certoffset))
            msg += "\tCert size:               {} bytes\n".format(self.certsize)
            msg += "\tImage size:              {} bytes\n".format(self.imagesize)
            msg += "\tPartition size:          {} bytes\n\n".format(self.partition_size)
        else:
            msg += "There is no footer. \n\n"
        print(msg)


class HvbCert(object):
    CERTMAGIC = b'HVB\0'
    ALGORITHM_TYPES = {0 : 'SHA256_RSA3072',
                       1 : 'SHA256_RSA4096',
                       2 : 'SHA256_RSA2048',
                       3 : 'SM2'
                    }

    HASH_ALGORITHMS = {0 : 'SHA256',
                       1 : 'SHA128',
                       2 : 'SHA512',
                       3 : 'SM3'
                       }

    def __init__(self, cert=None):
        self.cert = cert

        flags = os.O_WRONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open('cert.bin', flags, modes), 'wb') as cert_fd:
            cert_fd.write(self.cert)

        if self.cert:
            self.mgc, self.major, self.minor = struct.unpack('4s2I', self.cert[0:12])
            self.version = '{}.{}'.format(self.major, self.minor)
            if self.mgc != self.CERTMAGIC:
                raise HvbError('Given cert does not look like a HVB cert.')
            self.img_org_len, self.img_len, self.partition = struct.unpack('2Q64s', self.cert[48:128])
            self.rollback_location, self.rollback_index = struct.unpack('2Q', self.cert[128:144])

            verity, self.hash_algo = struct.unpack('2I', self.cert[144:152])
            self.verity_type = 'hash' if verity == 1 else 'hashtree'
            self.salt_offset, self.salt_size = struct.unpack('2Q', self.cert[152:168])

            self.digest_offset, self.digest_size, self.hashtree_offset, self.hashtree_size, \
                        self.data_block_size, self.hash_block_size, self.fec_num_roots, \
                        self.fec_offset, self.fec_size = struct.unpack('9Q', self.cert[168:240])
            self.salt = struct.unpack('{}s'.format(self.salt_size), self.cert[240:240 + self.salt_size])
            self.digest = struct.unpack('{}s'.format(self.digest_size), \
                                        self.cert[240 + self.salt_size : 240 + self.salt_size + self.digest_size])
            hash_payload_size = self.salt_size + self.digest_size
            signature_info_offset = 240 + hash_payload_size
            self.algo, self.flags, self.key_offset, self.key_len = struct.unpack('2I2Q', \
                                    self.cert[signature_info_offset + 8 : signature_info_offset + 8 + 24])
            self.sig_content_offset, self.sig_content_bytes = struct.unpack('2Q', \
                                    self.cert[signature_info_offset + 32 : signature_info_offset + 32 + 16])
            self.userid_offset, self.userid_len = struct.unpack('QI', \
                                    self.cert[signature_info_offset + 48 : signature_info_offset + 48 + 12])
            print("userid_offset: {}, userid_len: {}".format(self.userid_offset, self.userid_len))
            self.key = self.cert[signature_info_offset + 112 : signature_info_offset + 112 + self.key_len]
            self.user_id = self.cert[signature_info_offset + 112 + self.key_len + self.sig_content_bytes : \
                            signature_info_offset + 112 + self.key_len + self.sig_content_bytes + self.userid_len]

        else:
            raise HvbError('Given cert is None.')

    def info_cert(self):
        msg = "[HVB cert]: \n"
        if self.cert:
            msg += "\tHVB tool version:           hvb tool {}\n".format(self.version)
            msg += "\tOriginal Image length:      {} bytes\n".format(self.img_org_len)
            msg += "\tImage length:               {} bytes (4K alignment)\n".format(self.img_len)
            msg += "\tPartition name:             {}\n".format(self.partition.decode())
            msg += "\tverity type(hash/hashtree): {}\n".format(self.verity_type)
            msg += "\tsalt size:                  {} bytes\n".format(self.salt_size)
            if self.hash_algo not in self.HASH_ALGORITHMS:
                raise HvbError("Unknown hash algorithm: {}".format(self.hash_algo))
            msg += "\tHash algorithm:             {}\n".format(self.HASH_ALGORITHMS[self.hash_algo])
            msg += "\tdigest size:                {} bytes\n".format(self.digest_size)
            msg += "\thashtree size:              {}\n".format(self.hashtree_size)
            msg += "\tfec size:                   {}\n".format(self.fec_size)
            msg += "\thashpayload:\n"
            msg += "\t\tsalt:               {}\n".format((binascii.b2a_hex(self.salt[0]).decode()))
            msg += "\t\tdigest:             {}\n".format((binascii.b2a_hex(self.digest[0]).decode()))
            if self.hashtree_size != 0:
                msg += "\t\thashtree offset: 0x{:x}\n".format(self.hashtree_offset)
            if self.fec_size != 0:
                msg += "\t\tfec offset:      0x{:x}\n".format(self.fec_offset)
            if self.algo not in self.ALGORITHM_TYPES:
                raise HvbError("Unknown algorithm type: {}".format(self.algo))
            msg += "\tAlgorithm:                  {}\n".format(self.ALGORITHM_TYPES[self.algo])
            msg += "\tUser id:                    {}\n".format(self.user_id.decode())
            if self.ALGORITHM_TYPES[self.algo] == 'SM2':
                msg += "\tPublic key:                 {}\n\n".format(binascii.b2a_hex(self.key).decode())
            else:
                msg += "\tPublic key (sha256):        {}\n\n".format(hashlib.sha256(self.key).hexdigest())
        else:
            msg += 'There is no certificate.\n\n'
        print(msg)

    def verify_signature(self, pubkey):
        if self.algo not in self.ALGORITHM_TYPES:
            raise HvbError("Unknown algorithm: {}".format(self.algo))
        algorithm_type = self.ALGORITHM_TYPES.get(self.algo)
        if algorithm_type not in ALGORITHMS:
            raise HvbError("Unknown algorithm type: {}".format(algorithm_type))
        algorithm = ALGORITHMS.get(algorithm_type)
        to_be_sig_content = self.cert[0 : self.sig_content_offset]
        sig_content = self.cert[self.sig_content_offset : self.sig_content_offset + self.sig_content_bytes]

        to_be_sig_content_bin = os.sep.join([os.getcwd(), 'tmp.{0}.bin'.format(os.getpid())])
        sig_content_bin = os.sep.join([os.getcwd(), 'sigcontent.{0}.bin'.format(os.getpid())])
        flags = os.O_RDONLY | os.O_WRONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(to_be_sig_content_bin, flags, modes), 'wb') as tmp_fd:
            tmp_fd.write(to_be_sig_content)
        with os.fdopen(os.open(sig_content_bin, flags, modes), 'wb') as tmp_fd:
            tmp_fd.write(sig_content)
        cmds = ['openssl', 'dgst', '-verify', pubkey, '-sigopt', 'rsa_padding_mode:pss',
               '-sigopt', 'rsa_pss_saltlen:32', '-sha256', '-signature', sig_content_bin, to_be_sig_content_bin]
        p = subprocess.Popen(cmds, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (pout, perr) = p.communicate(timeout=10)
        retcode = p.wait()
        if os.path.exists(sig_content_bin):
            os.remove(sig_content_bin)
        if os.path.exists(to_be_sig_content_bin):
            os.remove(to_be_sig_content_bin)
        print(pout.decode().strip())
        if retcode != 0:
            raise HvbError('Error verifying data: {}'.format(perr))
        if pout.decode().strip() != 'Verified OK':
            sys.stderr.write('Signature not correct\n')
            return False
        return True

    def verify_digest(self, image):
        image_size = self.img_org_len
        hash_algo = self.HASH_ALGORITHMS.get(self.hash_algo)
        salt = self.salt[0]
        if self.verity_type == 'hash':
            image.seek(0)
            image_content = image.read(image_size)
            hasher = hashlib.new(hash_algo, salt)
            hasher.update(image_content)
            digest = hasher.digest()
        elif self.verity_type == 'hashtree':
            hashtree_hasher = hashlib.new(hash_algo, salt)
            digest_size = len(hashtree_hasher.digest())
            digest_padding = 2 ** ((digest_size - 1).bit_length()) - digest_size
            remainder = image.block_size - image.img_size % image.block_size
            if remainder != image.block_size:
                image.append_raw(b'\0' * remainder)
            level_offsets, tree_size = calc_hashtree_size(image_size, image.block_size, digest_size)
            if hash_algo == 'SM3':
                digest, hashtree = generate_sm3_hash_tree(image, image_size, image.block_size,
                                                  hash_algo, level_offsets, tree_size)
            else:
                digest, hashtree = generate_sha_hash_tree(image, image_size, image.block_size,
                                                  hash_algo, salt, level_offsets, tree_size)
        else:
            print("[hvbtool][ERROR]: Invalid verity_type: %d", self.vertype)
            return False
        if self.digest[0] and digest != self.digest[0]:
            return False
        return True


class SMPublicKey(object):
    def __init__(self, pubkey):
        self.privkey = pubkey
        self.pubkey = b''

        cmds = ['openssl', 'ec', '-pubin', '-in', pubkey, '-text']
        process = subprocess.Popen(cmds, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            (out, err) = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            raise HvbError("Get public key timeout!")
        if process.wait() != 0:
            raise HvbError("Failed to get public key: {}".format(err))

        self.key_data = out.split(b'\n')
        self.pubkey_idx = self.key_data.index(b'pub:') + 1

    def get_public_key(self):
        for i in range(self.pubkey_idx, self.pubkey_idx + 5):    # The size of public key is 64 bytes, occupies 5 lines.
            self.pubkey += b''.join(self.key_data[i].strip().split(b':'))

        return binascii.a2b_hex(self.pubkey[2:])    # The prefix occupies two bytes.


class RSAPublicKey(object):
    MODULUS_PREFIX = b'modulus='
    BIT_LENGTH_KEYWORD = b'Public-Key:'

    def __init__(self, pubkey):
        self.pubkey = pubkey
        self.modulus_bits = self.get_bit_length(self.pubkey)
        cmds = ['openssl', 'rsa', '-in', pubkey, '-modulus', '-noout', '-pubin']
        process = subprocess.Popen(cmds, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            (out, err) = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            raise HvbError("Get public key timeout!")
        if process.wait() != 0:
            raise HvbError("Failed to get public key: {}".format(err))

        if not out.lower().startswith(self.MODULUS_PREFIX):
            raise HvbError('Invalid modulus')

        self.modulus = out[len(self.MODULUS_PREFIX):].strip()
        self.modulusdata = int(self.modulus, 16)
        self.exponent = 65537

    def get_bit_length(self, pubkey):
        bitlen = 0
        cmd = ['openssl', 'rsa',  '-inform', 'PEM',  '-in', pubkey,  '-pubin', '-text']
        child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = child.stdout.read().split(b'\n')
        for line in lines:
            if self.BIT_LENGTH_KEYWORD in line:
                bitlen = int(re.findall(b'\d+', line.split(self.BIT_LENGTH_KEYWORD)[-1])[0])
                break
        return bitlen

    def calc_egcd(self, num1, num2):
        if num1 == 0:
            return (num2, 0, 1)
        egcd_g, egcd_y, egcd_x = self.calc_egcd(num2 % num1, num1)
        return (egcd_g, egcd_x - (num2 // num1) * egcd_y, egcd_y)

    def calc_modinv(self, num1, modulo):
        modinv_gcd, modinv_x, _ = self.calc_egcd(num1, modulo)
        if modinv_gcd != 1:
            raise HvbError("modular inverse does not exist.")
        return modinv_x % modulo

    def get_public_key(self):
        pkey_n0 = 2 ** 64 - self.calc_modinv(self.modulusdata, 2 ** 64)
        pkey_r = 2 ** self.modulusdata.bit_length()
        pkey_prr = bytes(encode_long(self.modulus_bits, pkey_r * pkey_r % self.modulusdata))
        modulus = bytes(encode_long(self.modulus_bits, self.modulusdata))

        return struct.pack('!QQ', self.modulus_bits, pkey_n0) + modulus + pkey_prr


class HvbError(Exception):
    def __init__(self, message):
        print("[HvbError]: " + message)
        Exception.__init__(self, message)


class ImageChunk(object):
    CHUNK_HEADER_FORMAT = '<2H2I'
    CHUNK_HEADER_SIZE = struct.calcsize(CHUNK_HEADER_FORMAT)
    CHUNK_TYPE_RAW = 0xcac1
    CHUNK_TYPE_FILL = 0xcac2
    CHUNK_TYPE_DONT_CARE = 0xcac3
    CHUNK_TYPE_CRC32 = 0xcac4

    def __init__(self, chunk_type, chunk_offset, nsparsed_output_offset,
                 nsparsed_output_size, input_offset, fill_data):
        """Initializes an ImageChunk object.

            Arguments:
              chunk_type: One of TYPE_RAW, TYPE_FILL, or TYPE_DONT_CARE.
              chunk_offset: Offset in the sparse file where this chunk begins.
              output_offset: Offset in de-sparsified file.
              output_size: Number of bytes in output.
              input_offset: Offset in sparse file where the chunk data begins if TYPE_RAW otherwise None.
              fill_data: Blob as bytes with data to fill if TYPE_FILL otherwise None.
            """

        self.chunk_type = chunk_type
        self.chunk_offset = chunk_offset
        self.nsparsed_chunk_offset = nsparsed_output_offset
        self.nsparsed_output_size = nsparsed_output_size
        self.sparsed_input_offset = input_offset
        self.fill_data = fill_data
        # Check invariants.
        if self.chunk_type == self.CHUNK_TYPE_RAW:
            if self.fill_data is not None:
                raise HvbError('RAW chunk cannot have fill_data set.')
            if not self.sparsed_input_offset:
                raise HvbError('RAW chunk must have input_offset set.')
        elif self.chunk_type == self.CHUNK_TYPE_FILL:
            if self.fill_data is None:
                raise HvbError('FILL chunk must have fill_data set.')
            if self.sparsed_input_offset:
                raise HvbError('FILL chunk cannot have input_offset set.')
        elif self.chunk_type == self.CHUNK_TYPE_DONT_CARE:
            if self.fill_data is not None:
                raise HvbError('DONT_CARE chunk cannot have fill_data set.')
            if self.sparsed_input_offset:
                raise HvbError('DONT_CARE chunk cannot have input_offset set.')
        else:
            raise HvbError('Invalid chunk type')


class ImageHandle(object):
    #Descriptions of sparse image
    SIMAGE_MAGIC = 0xed26ff3a
    SIMAGE_HEADER_FORMAT = '<I4H4I'
    SIMAGE_HEADER_SIZE = struct.calcsize(SIMAGE_HEADER_FORMAT)

    def __init__(self, file_name):
        self.image_file = file_name
        self.is_sparse = False
        self.block_size = 4096    # A block size is 4096 bytes.
        self.total_blks = 0
        self.total_chunks = 0
        self.header_analyze()

    def header_analyze(self):
        self.img_handler = open(self.image_file, 'r+b')
        self.img_handler.seek(0, os.SEEK_END)
        self.img_size = self.img_handler.tell()
        print("Initial image length: ", self.img_size)

        self.img_handler.seek(0, os.SEEK_SET)
        header = self.img_handler.read(self.SIMAGE_HEADER_SIZE)

        """ Sparse header
            magic                  0xed26ff3a
            major_version          (0x1) - reject images with higher major versions
            minor_version          (0x0) - allow images with higer minor versions
            file_hdr_sz            28 bytes for first revision of the file format
            chunk_hdr_sz           12 bytes for first revision of the file format
            blk_sz                 block size in bytes, must be a multiple of 4 (4096)
            total_blks             total blocks in the non-sparse output image
            total_chunks           total chunks in the sparse input image
            image_checksum         CRC32 checksum of the original data, counting "don't care
                                   as 0. Standard 802.3 polynomial, use a Public Domain
                                   table implementation
        """
        (magic, major_version, minor_version, file_hdr_sz,
            chunk_hdr_sz, block_size, self.total_blks, self.total_chunks,
            img_checksum) = struct.unpack(self.SIMAGE_HEADER_FORMAT, header)
        if magic != self.SIMAGE_MAGIC:
            return

        self.block_size = block_size
        print("It's a sparse image.")
        if self.SIMAGE_HEADER_SIZE != file_hdr_sz:
            raise HvbError("Incorrect sparse image header size: {}".format(file_hdr_sz))
        if ImageChunk.CHUNK_HEADER_SIZE != chunk_hdr_sz:
            raise HvbError("Incorrect chunk header size: {}".format(chunk_hdr_sz))

        self.chunks = list()
        nsparsed_output_offset, nsparsed_chunk_nums = self.chunk_analyze()
        self.sparse_end = self.img_handler.tell()

        if self.total_blks != nsparsed_chunk_nums:
            raise HvbError("The header said we should have {} output blocks, "
                               'but we saw {}'.format(self.total_blks, nsparsed_chunk_nums))
        if self.sparse_end != self.img_size:
            raise HvbError("There were {} bytes of extra data at the end of the "
                               "file.".format(self.img_size - self.sparse_end))

        self.nsparsed_chunk_offset_list = [c.nsparsed_chunk_offset for c in self.chunks]
        self.is_sparse = True
        self.img_size = nsparsed_output_offset

    def chunk_analyze(self):
        nsparsed_output_offset = 0
        nsparsed_chunk_nums = 0

        for i in range(self.total_chunks):
            chunk_offset = self.img_handler.tell()

            """ chunk header
                chunk_type             Type of this chunk (Raw, Fill, Dont care, CRC32)
                chunk_sz               Size of the chunk before the sparse(The unit is blk_sz, that is, 4096)
                total_sz               The size of the chunk after sparse, includes chunk_header and chunk data.
            """
            chunk_header = self.img_handler.read(ImageChunk.CHUNK_HEADER_SIZE)
            (chunk_type, _, chunk_sz, total_sz) = struct.unpack(ImageChunk.CHUNK_HEADER_FORMAT, chunk_header)
            chunk_data_size = total_sz - ImageChunk.CHUNK_HEADER_SIZE

            if chunk_type == ImageChunk.CHUNK_TYPE_RAW:
                if chunk_data_size != (chunk_sz * self.block_size):
                    raise HvbError("Raw chunk size ({}) does not match output "
                                    "size ({})".format(chunk_data_size, (chunk_sz * self.block_size)))
                self.chunks.append(ImageChunk(ImageChunk.CHUNK_TYPE_RAW, chunk_offset,
                                                  nsparsed_output_offset, chunk_sz * self.block_size,
                                                  self.img_handler.tell(), None))
                self.img_handler.seek(chunk_data_size, os.SEEK_CUR)
            elif chunk_type == ImageChunk.CHUNK_TYPE_FILL:
                if chunk_data_size != 4:
                    raise HvbError("Fill chunk should have 4 bytes of fill, but this "
                                       "has {}".format(chunk_data_size))
                fill_data = self.img_handler.read(4)
                self.chunks.append(ImageChunk(ImageChunk.CHUNK_TYPE_FILL, chunk_offset,
                                                  nsparsed_output_offset, chunk_sz * self.block_size,
                                                  None, fill_data))
            elif chunk_type == ImageChunk.CHUNK_TYPE_DONT_CARE:
                if chunk_data_size != 0:
                    raise HvbError("Don\'t care chunk input size is non-zero ({})".
                                       format(chunk_data_size))
                self.chunks.append(ImageChunk(ImageChunk.CHUNK_TYPE_DONT_CARE, chunk_offset,
                                                  nsparsed_output_offset, chunk_sz * self.block_size,
                                                  None, None))
            elif chunk_type == ImageChunk.CHUNK_TYPE_CRC32:
                if chunk_data_size != 4:
                    raise HvbError("CRC32 chunk should have 4 bytes of CRC, but "
                                       "this has {}".format(chunk_data_size))
                self.img_handler.read(4)
            else:
                raise HvbError("Unknown chunk type: {}".format(chunk_type))

            nsparsed_chunk_nums += chunk_sz
            nsparsed_output_offset += chunk_sz * self.block_size

        return nsparsed_output_offset, nsparsed_chunk_nums

    def update_chunks_and_blocks(self):
        """Helper function to update the image header.

        The the |total_chunks| and |total_blocks| fields in the header
        will be set to value of the |_num_total_blocks| and
        |_num_total_chunks| attributes.

        """
        num_chunks_and_blocks_offset = 16
        num_chunks_and_blocks_format = '<II'
        self.img_handler.seek(num_chunks_and_blocks_offset, os.SEEK_SET)
        self.img_handler.write(struct.pack(num_chunks_and_blocks_format,
                                      self.total_blks, self.total_chunks))

    def append_dont_care(self, num_bytes):
        """Appends a DONT_CARE chunk to the sparse file.

        The given number of bytes must be a multiple of the block size.

        Arguments:
          num_bytes: Size in number of bytes of the DONT_CARE chunk.

        """
        if num_bytes % self.block_size != 0:
            raise HvbError("Given number of bytes must be a multiple of the block size.")

        if not self.is_sparse:
            self.img_handler.seek(0, os.SEEK_END)
            # This is more efficient that writing NUL bytes since it'll add
            # a hole on file systems that support sparse files (native
            # sparse, not OpenHarmony sparse).
            self.img_handler.truncate(self.img_handler.tell() + num_bytes)
            self.header_analyze()
            return

        self.total_chunks += 1
        self.total_blks += num_bytes // self.block_size
        self.update_chunks_and_blocks()

        self.img_handler.seek(self.sparse_end, os.SEEK_SET)
        self.img_handler.write(struct.pack(ImageChunk.CHUNK_HEADER_FORMAT,
                                      ImageChunk.CHUNK_TYPE_DONT_CARE,
                                      0,  # Reserved
                                      num_bytes // self.block_size,
                                      struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT)))
        self.header_analyze()

    def append_raw(self, data):
        """Appends a RAW chunk to the sparse file.

        The length of the given data must be a multiple of the block size.

        Arguments:
          data: Data to append as bytes.

        """
        print("SELF>BLOCK_SIZE: ", self.block_size)
        if len(data) % self.block_size != 0:
            raise HvbError("Given data must be a multiple of the block size.")

        if not self.is_sparse:
            self.img_handler.seek(0, os.SEEK_END)
            self.img_handler.write(data)
            self.header_analyze()
            return

        self.total_chunks += 1
        self.total_blks += len(data) // self.block_size
        self.update_chunks_and_blocks()

        self.img_handler.seek(self.sparse_end, os.SEEK_SET)
        self.img_handler.write(struct.pack(ImageChunk.CHUNK_HEADER_FORMAT,
                                      ImageChunk.CHUNK_TYPE_RAW,
                                      0,  # Reserved
                                      len(data) // self.block_size,
                                      len(data) +
                                      struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT)))
        self.img_handler.write(data)
        self.header_analyze()

    def append_fill(self, fill_data, size):
        """Appends a fill chunk to the sparse file.

        The total length of the fill data must be a multiple of the block size.

        Arguments:
          fill_data: Fill data to append - must be four bytes.
          size: Number of chunk - must be a multiple of four and the block size.

        """
        if len(fill_data) != 4 or size % 4 != 0 or size % self.block_size != 0:
            raise HvbError("The total length of the fill data must be a multiple of the block size.")

        if not self.is_sparse:
            self.img_handler.seek(0, os.SEEK_END)
            self.img_handler.write(fill_data * (size // 4))
            self.header_analyze()
            return

        self.total_chunks += 1
        self.total_blks += size // self.block_size
        self.update_chunks_and_blocks()

        self.img_handler.seek(self.sparse_end, os.SEEK_SET)
        self.img_handler.write(struct.pack(ImageChunk.CHUNK_HEADER_FORMAT,
                                      ImageChunk.CHUNK_TYPE_FILL,
                                      0,  # Reserved
                                      size // self.block_size,
                                      4 + struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT)))
        self.img_handler.write(fill_data)
        self.header_analyze()

    def seek(self, offset):
        """Sets the cursor position for reading from unsparsified file.

        Arguments:
          offset: Offset to seek to from the beginning of the file.

        Raises:
          RuntimeError: If the given offset is negative.
        """
        if offset < 0:
            raise RuntimeError('Seeking with negative offset: {}'.format(offset))
        self._file_pos = offset

    def read(self, size):
        """Reads data from the unsparsified file.

        This method may return fewer than |size| bytes of data if the end
        of the file was encountered.

        The file cursor for reading is advanced by the number of bytes
        read.

        Arguments:
          size: Number of bytes to read.

        Returns:
          The data as bytes.
        """
        if not self.is_sparse:
            self.img_handler.seek(self._file_pos)
            data = self.img_handler.read(size)
            self._file_pos += len(data)
            return data

        # Iterate over all chunks.
        chunk_idx = bisect.bisect_right(self.nsparsed_chunk_offset_list,
                                        self._file_pos) - 1
        data = bytearray()
        to_go = size
        while to_go > 0:
            chunk = self.chunks[chunk_idx]
            chunk_pos_offset = self._file_pos - chunk.nsparsed_chunk_offset
            chunk_pos_to_go = min(chunk.nsparsed_output_size - chunk_pos_offset, to_go)

            if chunk.chunk_type == ImageChunk.CHUNK_TYPE_RAW:
                self.img_handler.seek(chunk.sparsed_input_offset + chunk_pos_offset)
                data.extend(self.img_handler.read(chunk_pos_to_go))
            elif chunk.chunk_type == ImageChunk.CHUNK_TYPE_FILL:
                all_data = chunk.fill_data * (chunk_pos_to_go // len(chunk.fill_data) + 2)
                offset_mod = chunk_pos_offset % len(chunk.fill_data)
                data.extend(all_data[offset_mod:(offset_mod + chunk_pos_to_go)])
            else:
                if chunk.chunk_type != ImageChunk.CHUNK_TYPE_DONT_CARE:
                    raise HvbError("Invalid chunk type!")
                data.extend(b'\0' * chunk_pos_to_go)

            to_go -= chunk_pos_to_go
            self._file_pos += chunk_pos_to_go
            chunk_idx += 1
            # Generate partial read in case of EOF.
            if chunk_idx >= len(self.nsparsed_chunk_offset_list):
                break

        return bytes(data)

    def tell(self):
        """Returns the file cursor position for reading from unsparsified file.

        Returns:
          The file cursor position for reading.
        """
        return self._file_pos

    def truncate(self, size):
        """Truncates the unsparsified file.

        Arguments:
          size: Desired size of unsparsified file.

        Raises:
          ValueError: If desired size isn't a multiple of the block size.
        """

        if not self.is_sparse:
            self.img_handler.truncate(size)
            self.header_analyze()
            return

        if size % self.block_size != 0:
            raise ValueError('Cannot truncate to a size which is not a multiple '
                             'of the block size')

        if size == self.img_size:
            # Trivial where there's nothing to do.
            return

        if size < self.img_size:
            chunk_idx = bisect.bisect_right(self.nsparsed_chunk_offset_list, size) - 1
            chunk = self.chunks[chunk_idx]
            if chunk.nsparsed_chunk_offset != size:
                # Truncation in the middle of a trunk - need to keep the chunk
                # and modify it.
                chunk_idx_for_update = chunk_idx + 1
                num_to_keep = size - chunk.nsparsed_chunk_offset
                if num_to_keep % self.block_size != 0:
                    raise HvbError("Remainder size of bytes must be multiple of the block size.")

                if chunk.chunk_type == ImageChunk.CHUNK_TYPE_RAW:
                    truncate_at = (chunk.nsparsed_chunk_offset +
                                   struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT) + num_to_keep)
                    data_sz = num_to_keep
                elif chunk.chunk_type == ImageChunk.CHUNK_TYPE_FILL:
                    truncate_at = (chunk.nsparsed_chunk_offset +
                                   struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT) + 4)
                    data_sz = 4
                elif chunk.chunk_type == ImageChunk.CHUNK_TYPE_DONT_CARE:
                    truncate_at = chunk.nsparsed_chunk_offset + struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT)
                    data_sz = 0
                else:
                    raise HvbError("Invalid chunk type.")
                chunk_sz = num_to_keep // self.block_size
                total_sz = data_sz + struct.calcsize(ImageChunk.CHUNK_HEADER_FORMAT)
                self.img_handler.seek(chunk.nsparsed_chunk_offset)
                self.img_handler.write(struct.pack(ImageChunk.CHUNK_HEADER_FORMAT,
                                              chunk.chunk_type,
                                              0,  # Reserved
                                              chunk_sz, total_sz))
                chunk.output_size = num_to_keep
            else:
                # Truncation at trunk boundary.
                truncate_at = chunk.chunk_offset
                chunk_idx_for_update = chunk_idx

            self.total_chunks = chunk_idx_for_update
            self.total_blks = 0
            for i in range(0, chunk_idx_for_update):
                self.total_blks += self.chunks[i].nsparsed_output_size // self.block_size
            self.update_chunks_and_blocks()
            self.img_handler.truncate(truncate_at)

            # We've modified the file so re-read all data.
            self.header_analyze()
        else:
            # Truncating to grow - just add a DONT_CARE section.
            self.append_dont_care(size - self.img_size)


class HvbTool(object):
    MAGIC = b'HVB\0'
    HVB_VERSION_MAJOR = 1
    HVB_VERSION_MINOR = 1
    FOOTER_SIZE = 104
    VERITY_RESERVED = b'\0' * 36
    RVT_MAGIC = b'rot\0'

    MAX_RVT_SIZE = 64 * 1024
    MAX_FOOTER_SIZE = 4096
    RVT_RESERVED = 60


    def __init__(self):
        self.img = _params['image']
        self.partition = _params['partition']
        self.partition_size = int(_params['partition_size'])
        self.vertype = _params['verity_type'].lower()  # verity type: hash - 1 or hashtree - 2 (fix)
        self.algo = _params['algorithm']
        self.user_id = _params['userid']
        self.pubkey = _params['pubkey']
        self.privkey = _params['privkey']
        self.block_size = _params['block_size']
        self.padding_size = _params['padding_size']
        self.signing_helper_with_files = _params['signing_helper_with_files']
        self.pubkey_num_per_ptn = int(_params['pubkey_num_per_ptn'])
        self.calc_max_image_size = _params['calc_max_image_size'].lower()
        self.signed_img = _params['output']
        self.hash_algo = ALGORITHMS[self.algo].hash_algo

        if _params['salt'] is not None:
            self.salt = binascii.a2b_hex(_params['salt'])

        if self.algo == 'SM2' and self.user_id is None:
            self.user_id = create_random_data(16)    # Set user_id 16 bytes
            print("USERID: {}".format(self.user_id))

        self.hashtree = b''
        self.digest = b''
        self.fec = b''
        self.hvb_cert_content = b''

        self.hvb_calc_max_image()
        self.original_image_info()

    def original_image_info(self):
        if self.img is None:
            return

        self.image_handle = ImageHandle(self.img)
        self.original_image_length = self.image_handle.img_size
        # Image length algins to 4096 bytes
        self.img_len_with_padding = round_to_multiple(self.original_image_length, self.block_size)
        print("Image length(%s): %d bytes" % (self.img, self.original_image_length))

    def hvb_header(self):
        self.hvb_cert_content = self.MAGIC
        self.hvb_cert_content += struct.pack('I', self.HVB_VERSION_MAJOR)
        self.hvb_cert_content += struct.pack('I', self.HVB_VERSION_MINOR)
        self.hvb_cert_content += self.VERITY_RESERVED

    def hvb_image_info(self):
        max_partition_name_len = 64
        partition_name = (self.partition).encode('utf-8') + b'\0' * (max_partition_name_len - len(self.partition))

        self.hvb_cert_content += struct.pack('Q', self.original_image_length)
        self.hvb_cert_content += struct.pack('Q', self.img_len_with_padding)
        self.hvb_cert_content += partition_name
        self.hvb_cert_content += struct.pack('2Q', int(_params['rollback_location']), int(_params['rollback_index']))

    def image_hash(self):
        # 0: SHA256    1: SHA128    2: SHA512    3：SM3
        halgo = HASH_ALGORITHM[ALGORITHMS[self.algo].hash_algo]
        print("HALGO: {}".format(halgo))

        print("digest: {}".format(binascii.b2a_hex(self.digest)))
        print("digest size: ", len(self.digest))

        hash_algo = struct.pack('I', halgo)
        salt_offset = struct.pack('Q', 240)       # 根据HVB证书格式，salt偏移位置固定，为240字节的偏移
        salt_size = struct.pack('Q', len(self.salt))
        digest_offset = struct.pack('Q', 240 + len(self.salt))
        digest_size = struct.pack('Q', len(self.digest))
        return hash_algo + salt_offset + salt_size + digest_offset + digest_size

    def create_hashtree(self, digest_size):
        size = self.image_handle.img_size

        level_offsets, tree_size = calc_hashtree_size(size, self.block_size, digest_size)
        print("level_offsets: {}, tree_size: {}".format(level_offsets, tree_size))
        if self.hash_algo == 'SM3':
            rootdigest, self.hashtree = generate_sm3_hash_tree(self.image_handle, size, self.block_size, level_offsets, tree_size)
        else:
            rootdigest, self.hashtree = generate_sha_hash_tree(self.image_handle, size, self.block_size, self.hash_algo,
                                                       self.salt, level_offsets, tree_size)
        if len(self.hashtree) % self.block_size != 0:
            self.hashtree += b'\0' * (self.block_size - len(self.hashtree) % self.block_size)
        print("root digest: ", binascii.b2a_hex(rootdigest))
        return rootdigest

    def image_hash_tree(self):
        image_hashtree = {"hashtree_offset": self.img_len_with_padding, \
                          "hashtree_size": len(self.hashtree), "data_block_size": self.block_size, \
                          "hash_block_size": self.block_size, "fec_num_roots": 0, \
                          "fec_offset": 240 + len(self.salt) + len(self.digest), "fec_size": 0}
        hashtree_struct = struct.Struct('Q' * len(image_hashtree))
        dlist = []
        for item in image_hashtree:
            dlist.append(image_hashtree[item])
        return hashtree_struct.pack(*dlist)

    def hvb_hash_info(self):
        verity_type = 0

        if self.vertype == 'hash':
            verity_type = 1    # hash: 1    hashtree: 2

            if self.hash_algo == 'SM3':
                self.digest = get_sm3_digest(self.img)
            else:
                self.image_handle.seek(0)
                image_content = self.image_handle.read(self.image_handle.img_size)
                self.digest = get_sha256_digest(self.hash_algo, self.salt, image_content)
        elif self.vertype == 'hashtree':
            verity_type = 2    # hash: 1    hashtree: 2

            if self.hash_algo == 'SM3':
                digest_size = ALGORITHMS[self.algo].hash_bytes
            else:
                hashtree_hasher = hashlib.new(self.hash_algo, self.salt)
                digest_size = len(hashtree_hasher.digest())
            digest_padding = 2 ** ((digest_size - 1).bit_length()) - digest_size
            print("hash_algo: {}, salt: {}".format(self.hash_algo, self.salt))
            print("digest_size: {}, digest_padding: {}".format(digest_size, digest_padding))
            remainder = self.block_size - self.image_handle.img_size % self.block_size
            if remainder != self.block_size:
                self.image_handle.append_raw(b'\0' * remainder)
            self.img_len_with_padding = self.image_handle.img_size
            self.digest = self.create_hashtree(digest_size + digest_padding)
        else:
            print("[hvbtool][ERROR]: Invalid verity_type: %d", self.vertype)
            sys.exit(1)

        imghash = self.image_hash()
        imghashtree = self.image_hash_tree()
        hashpayload = self.salt + self.digest

        hashinfo = struct.pack('I', verity_type) + imghash + imghashtree + hashpayload
        self.hashinfo_size = len(hashinfo)
        self.hvb_cert_content += hashinfo

    def get_sign_command(self, sig_content_bin, to_be_sig_content_bin):
        if self.algo == 'SM2':
            cmd = [
                    'openssl', 'dgst',  '-SM3', '-sign', self.privkey, '-sigopt', 'distid:{}'.format(self.user_id),
                    '-out', sig_content_bin, to_be_sig_content_bin
            ]
        else:
            cmd = [
                    'openssl', 'dgst', '-sign', self.privkey, '-sigopt',  'rsa_padding_mode:pss',
                    '-sigopt', 'rsa_pss_saltlen:{}'.format(len(self.salt)), '-sha256', '-out',
                    sig_content_bin,  to_be_sig_content_bin
            ]

        return cmd

    def hvb_signature_info(self):
        sig_content_bin = os.sep.join([os.getcwd(), 'sigcontent.{0}.bin'.format(os.getpid())])
        to_be_sig_content_bin = os.sep.join([os.getcwd(), 'tmp.{0}.bin'.format(os.getpid())])
        # 签名算法  0：SHA256_RSA3072（默认值）, 1：SHA256_RSA4096 , 2：SHA256_RSA2048
        if self.algo not in ALGORITHMS:
            raise HvbError("Unknown algorithm: {}".format(self.algo))
        algo = ALGORITHMS[self.algo]
        flags = 0       # 预留的flag标记，默认全为0
        user_id_len = 0
        userid = b''

        if self.user_id is not None:
            user_id_len = len(self.user_id)
            userid = self.user_id.encode()

        keyblock_offset = 144 + self.hashinfo_size + 112

        try:
            if self.algo == "SM2":
                key = SMPublicKey(self.pubkey)
            else:
                key = RSAPublicKey(self.pubkey)
        except HvbError as err:
            sys.exit(1)
        keyblock = key.get_public_key()

        signature_offset = keyblock_offset + len(keyblock)
        sig_length = len(self.hvb_cert_content) + 112 + len(keyblock)
        user_id_offset = signature_offset + algo.sig_bytes

        print("user_id_offset: {}, user_id_len: {}".format(user_id_offset, user_id_len))

        self.hvb_cert_content += struct.pack('Q', sig_length) + struct.pack('I', algo.sig_algo) \
                        + struct.pack('I', flags) + struct.pack('Q', keyblock_offset) \
                        + struct.pack('Q', len(keyblock)) + struct.pack('Q', signature_offset) \
                        + struct.pack('Q', algo.sig_bytes) + struct.pack('Q', user_id_offset)  \
                        + struct.pack('I', user_id_len) + b'\0' * 52 + keyblock    # reserved 52 bytes

        if os.path.exists(sig_content_bin):
            os.remove(sig_content_bin)

        flags = os.O_WRONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(to_be_sig_content_bin, flags, modes), 'wb') as tmp_fd:
            tmp_fd.write(self.hvb_cert_content)

        if self.signing_helper_with_files is not None:
            if len(self.salt) != 32:
                raise HvbError("Salt len must be 32 bit, but current salt len is {} bit!".format(len(self.salt)))
            p = subprocess.Popen([self.signing_helper_with_files, self.algo,
                                  self.pubkey, to_be_sig_content_bin, sig_content_bin])
            ret = p.wait()
            if ret != 0:
                raise HvbError("Failed to sign the image by {}".format(self.signing_helper_with_files))
        else:
            self.get_signature_content(sig_content_bin, to_be_sig_content_bin)

        flags = os.O_RDONLY
        with os.fdopen(os.open(sig_content_bin, flags, modes), 'rb') as sig_fd:
            sigcontent = sig_fd.read()

        self.hvb_cert_content += sigcontent + userid

        if os.path.exists(sig_content_bin):
            os.remove(sig_content_bin)
        if os.path.exists(to_be_sig_content_bin):
            os.remove(to_be_sig_content_bin)

    def get_signature_content(self, sig_content_bin, to_be_sig_content_bin):
        cmd = self.get_sign_command(sig_content_bin, to_be_sig_content_bin)
        ret = subprocess.call(cmd)
        if ret != 0:
            raise HvbError("Failed to sign the image.")

        if self.algo == "SM2":
            flags = os.O_RDWR
            with os.fdopen(os.open(sig_content_bin, flags, stat.S_IWUSR | stat.S_IRUSR), 'r+b') as sig_fd:
                content = sig_fd.read()
                length = content[3]
                if length != 32 and length != 33:
                    raise HvbError("Invalid signature information.")

                begin = 4 + length % 32
                end = begin + 32
                data1 = content[begin : end]

                length = content[end + 1]
                if length != 32 and length != 33:
                    raise HvbError("Invalid signature information.")
                begin = end + 2 + length % 32
                end = begin + 32
                data2 = content[begin : end]

                data = b''.join([data1, data2])
                sig_fd.seek(0)
                sig_fd.truncate()
                sig_fd.write(data)

    def hvb_footer_info(self):
        self.footer = b''
        footer_magic = self.MAGIC + b'\0' * 4
        self.partition_size = int(self.partition_size)

        cert_size = len(self.hvb_cert_content)
        cert_offset = self.img_len_with_padding + len(self.hashtree)

        if self.padding_size is not None:
            cert_offset = self.partition_size - self.padding_size

        print("cert_size: %x, cert_offset: %x, partition_size: %x" % (cert_size, cert_offset, self.partition_size))
        self.footer += footer_magic \
                       + struct.pack('4Q', cert_offset, cert_size, self.original_image_length, self.partition_size) \
                       + b'\0' * 64

    def hvb_make_rvt_image(self):
        self.img = 'tmp_{0}_rvt.img'.format(os.getpid())
        rvtcontent = b''
        rvtcontent += self.RVT_MAGIC
        verity_num = len(_params['chain_partition'])
        if self.pubkey_num_per_ptn != 1 and self.pubkey_num_per_ptn != 2:
            print("invalid pubkey_num_per_ptn: %d" % (self.pubkey_num_per_ptn))
            sys.exit(1)
        if verity_num % self.pubkey_num_per_ptn != 0:
            print("verity_num doesnt match pubkey_num_per_ptn: %d" % (self.pubkey_num_per_ptn))
            sys.exit(1)
        rvtcontent += struct.pack('I', verity_num // self.pubkey_num_per_ptn)
        rvtcontent += struct.pack('I', self.pubkey_num_per_ptn) + b'\0' * self.RVT_RESERVED # rvt_reversed: 60 bytes
        cur_sizes = len(rvtcontent)

        for index in range(0, verity_num, self.pubkey_num_per_ptn):
            chain_partition_data = _params['chain_partition'][index].split(':')
            partition_name = chain_partition_data[0].strip()
            pubkey = chain_partition_data[1].strip()
            if self.pubkey_num_per_ptn == 2:
                chain_partition_data_backup = _params['chain_partition'][index + 1].split(':')
                partition_name_backup = chain_partition_data_backup[0].strip()
                if partition_name != partition_name_backup:
                    print("partition name doesnt match for pubkey_num_per_ptn: %d" % (self.pubkey_num_per_ptn))
                    sys.exit(1)
                pubkey_backup = chain_partition_data_backup[1].strip()

            try:
                if self.algo == 'SM2':
                    key = SMPublicKey(pubkey)
                    if self.pubkey_num_per_ptn == 2:
                        key_backup = SMPublicKey(pubkey_backup)
                else:
                    key = RSAPublicKey(pubkey)
                    if self.pubkey_num_per_ptn == 2:
                        key_backup = RSAPublicKey(pubkey_backup)
            except HvbError as err:
                sys.exit(1)
            pubkey_payload = key.get_public_key()
            if self.pubkey_num_per_ptn == 2:
                pubkey_payload_backup = key_backup.get_public_key()
            pubkey_len = len(pubkey_payload)
            pubkey_offset = cur_sizes + 80
            rvtcontent += partition_name.encode() + b'\0' * (64 - len(partition_name))    # partition_name
            rvtcontent += struct.pack('Q', pubkey_offset) # pubkey_offset
            rvtcontent += struct.pack('Q', pubkey_len)    # pubkey_len
            rvtcontent += pubkey_payload  # pubkey_payload
            if self.pubkey_num_per_ptn == 2:
                rvtcontent += pubkey_payload_backup  # pubkey_payload_backup
            cur_sizes += 80 + pubkey_len * self.pubkey_num_per_ptn

        flags = os.O_WRONLY | os.O_RDONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(self.img, flags, modes), 'wb') as rvt_fd:
            rvt_fd.write(rvtcontent)

        self.original_image_info()
        self.hvb_make_image()

        if os.path.exists(self.img):
            os.remove(self.img)

    def hvb_combine_image_info(self):
        cert_and_footer = b''
        hashtree_length = len(self.hashtree)
        hvb_cert_length = len(self.hvb_cert_content)
        image = os.path.abspath(self.img)
        signed_image = os.path.abspath(self.signed_img)

        shutil.copy(image, signed_image)
        image = ImageHandle(signed_image)

        padding = round_to_multiple(image.img_size, self.block_size)
        if padding > image.img_size:
            if image.is_sparse is True:     # Original image size must be multiple of block_size
                raise HvbError("The sparse image size is not multiple of the block size.")
            image.truncate(padding)

        padding = round_to_multiple((hvb_cert_length + self.FOOTER_SIZE), self.block_size)
        if padding > (hvb_cert_length + self.FOOTER_SIZE):
            cert_and_footer = self.hvb_cert_content + b'\0' * (padding - (self.FOOTER_SIZE + hvb_cert_length)) + \
                self.footer
        else:
            cert_and_footer = self.hvb_cert_content + self.footer

        if self.partition_size < image.img_size + hashtree_length + len(cert_and_footer):
            raise HvbError("[hvbtool][ERROR]: Partition size is too small!")

        cert_and_footer = self.hvb_cert_content + b'\0' * (self.partition_size - image.img_size - \
            hashtree_length - hvb_cert_length - self.FOOTER_SIZE) + self.footer
        image.append_raw(self.hashtree)
        image.append_raw(cert_and_footer)
        if image.img_handler:
            image.img_handler.close()

    def parse_rvt_image(self, handle):
        handle.seek(0)

        header = handle.read(12)
        magic, verity_num, pubkey_num_per_ptn = struct.unpack('4sII', header)

        msg = ["[rvt info]: \n"]
        if magic != self.RVT_MAGIC:
            raise HvbError("It is not a valid rvt image.")

        if pubkey_num_per_ptn == 0:
            pubkey_num_per_ptn = 1
            msg.append("\tuse old version pubkey_num_per_ptn\n")
        msg.append("\tpubkey_num_per_ptn:          {}\n".format(pubkey_num_per_ptn))

        handle.seek(72)
        for i in range(verity_num):
            # The size of pubkey_des excludes pubkey_payload is 80 bytes
            data = handle.read(80)
            name, pubkey_offset, pubkey_len = struct.unpack('64s2Q', data)
            msg.append('\n\tChain Partition descriptor: \n')
            msg.append('\t\tPartition Name:      {}\n'.format(name.decode()))
            pubkey = handle.read(pubkey_len)
            msg.append("\t\tPublic key:          {}\n".format(hashlib.sha256(pubkey).hexdigest()))
            if pubkey_num_per_ptn == 2:
                pubkey_backup = handle.read(pubkey_len)
                msg.append("\t\tBackup Public key:   {}\n".format(hashlib.sha256(pubkey_backup).hexdigest()))

        print(''.join(msg))

    def hvb_calc_max_image(self):
        if self.calc_max_image_size == "true":
            max_metadata_size = self.MAX_RVT_SIZE + self.MAX_FOOTER_SIZE

            if self.vertype == 'hashtree':
                hashtree_hasher = hashlib.new(self.hash_algo, self.salt)
                digest_size = len(hashtree_hasher.digest())
                digest_padding = 2 ** ((digest_size - 1).bit_length()) - digest_size

                _, hashtree_size = calc_hashtree_size(self.partition_size, self.block_size, digest_size)
                max_metadata_size += hashtree_size

            max_image_size = self.partition_size - max_metadata_size
            print("\ncalc_max_image_size: {}".format(max_image_size))
            sys.exit(0)

    def hvb_make_image(self):
        self.hvb_header()
        self.hvb_image_info()
        self.hvb_hash_info()
        self.hvb_signature_info()
        self.hvb_footer_info()
        self.hvb_combine_image_info()

    def hvb_parse_image(self):
        try:
            image = ImageHandle(self.img)
            image.seek(self.original_image_length - self.FOOTER_SIZE)
            footer_bin = image.read(self.FOOTER_SIZE)
            footer = HvbFooter(footer_bin)
            footer.info_footer()

            image.seek(footer.certoffset)
            cert_bin = image.read(footer.certsize)
            cert = HvbCert(cert_bin)
            cert.info_cert()

            if 'rvt' in cert.partition.decode():
                self.parse_rvt_image(image)
        except (HvbError, struct.error):
            raise HvbError("Failed to parse the image!")
        finally:
            if image.img_handler:
                image.img_handler.close()

    def hvb_erase_image(self):
        try:
            image = ImageHandle(self.img)
            image.seek(self.original_image_length - self.FOOTER_SIZE)
            footer_bin = image.read(self.FOOTER_SIZE)
            footer = HvbFooter(footer_bin)
            image.seek(0)
            image.truncate(footer.imagesize)
        except (HvbError, struct.error):
            raise HvbError("Failed to erase image.")
        finally:
            if image.img_handler:
                image.img_handler.close()

    def hvb_verify_image(self):
        try:
            key_blob = RSAPublicKey(self.pubkey).get_public_key()
            print('Verifying image {} using key at {}'.format(self.img, self.pubkey))
        except HvbError as err:
            print('Pubkey {} is invalid!'.format(self.pubkey))
            sys.exit(1)

        try:
            image = ImageHandle(self.img)
            image.seek(self.original_image_length - self.FOOTER_SIZE)
            footer_bin = image.read(self.FOOTER_SIZE)
            footer = HvbFooter(footer_bin)

            image.seek(footer.certoffset)
            cert_bin = image.read(footer.certsize)
            cert = HvbCert(cert_bin)
            if key_blob and key_blob != cert.key:
                raise HvbError('Embedded public key does not match given key.')
            if not cert.verify_signature(self.pubkey):
                raise HvbError('Failed check signature for {}!'.format(self.img))
            if not cert.verify_digest(image):
                raise HvbError('Failed check digest for {}!'.format(self.img))
            print('Successfully verified hvb cert for {}!'.format(self.img))
        except (HvbError, struct.error):
            raise HvbError("Failed to verify image.")
        finally:
            if image.img_handler:
                image.img_handler.close()


def print_help():
    print("usage: hvbtool.py [-h]")
    print("\t\t{make_hash_footer, make_hashtree_footer, make_rvt_image, parse_image, erase_image}")


def parse_arguments(argvs):
    global _params
    length = len(argvs)
    i = 0
    args = list()

    if length % 2 != 0:
        print_help()
        print("[hvbtool][ERROR]: invalid argument format!")
        sys.exit(1)

    while (i < length):
        args.append([argvs[i], argvs[i + 1]])
        i = i + 2

    act = args[0][1]
    if act.strip() in VERITY_TYPE.keys():
        _params['verity_type'] = VERITY_TYPE[act]
    else:
        _params['verity_type'] = 'hash'

    for item in args[1:]:
        itemkey = item[0].strip()[2:]
        if itemkey in _params.keys():
            if itemkey == "chain_partition":
                _params[itemkey].append(item[1].strip())
            else:
                _params[itemkey] = item[1].strip()
        else:
            print("[hvbtool][ERROR]: Unknown argument: %s" % item[0])
            sys.exit(1)

    if  _params['salt'] is None:
        _params['salt'] = create_random_data()
    return act


def necessary_arguments_check(check_list):
    for item in check_list:
        if _params[item] is None or len(_params[item]) == 0:
            print("[hvbtool][ERROR]: The argument '{}' is necessary.".format(item))
            return False

    return True


def check_privkey_arg(act):
    if (act == 'make_hash_footer') or (act == 'make_hashtree_footer') or (act == 'make_rvt_image'):
        if _params['privkey'] is None and _params['signing_helper_with_files'] is None:
            print("[hvbtool][ERROR]: The argument 'privkey' is necessary.")
            sys.exit(1)


def check_arguments(act):
    make_image_arguments_list = ['image', 'algorithm', 'pubkey', 'rollback_index', 'rollback_location']
    make_rvt_image_arguments_list = ['algorithm', 'pubkey', 'rollback_index', 'rollback_location', 'chain_partition']
    parse_erase_image_arguments_list = ['image']
    verify_image_arguments_list = ['image', 'pubkey']
    ret = False

    if act == 'make_hash_footer' or act == 'make_hashtree_footer':
        ret = necessary_arguments_check(make_image_arguments_list)
    elif act == 'make_rvt_image':
        ret = necessary_arguments_check(make_rvt_image_arguments_list)
    elif act == 'parse_image' or act == 'erase_image':
        ret = necessary_arguments_check(parse_erase_image_arguments_list)
    elif act == 'verify_image':
        ret = necessary_arguments_check(verify_image_arguments_list)
    else:
        print("[hvbtool][ERROR]: Unkown action: {}".format(act))

    if ret is False:
        sys.exit(1)

    check_privkey_arg(act)


def main(obj, act):
    if act == 'make_hash_footer' or act == 'make_hashtree_footer':
        obj.hvb_make_image()
    elif act == 'parse_image':
        obj.hvb_parse_image()
    elif act == 'make_rvt_image':
        obj.hvb_make_rvt_image()
    elif act == 'erase_image':
        obj.hvb_erase_image()
    elif act == 'verify_image':
        obj.hvb_verify_image()
    else:
        raise HvbError("Unknown action: {}".format(act))

if __name__ == '__main__':
    action = parse_arguments(sys.argv)
    check_arguments(action)
    tool = HvbTool()
    try:
        main(tool, action)
    except (HvbError, struct.error):
        print("HVB COMMAND FAILED!")
        sys.exit(1)
    finally:
        if tool.image_handle.img_handler:
            tool.image_handle.img_handler.close()
    sys.exit(0)
