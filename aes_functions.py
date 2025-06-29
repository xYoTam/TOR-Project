__author__ = 'Ido Kaplan'
from tcp_by_size import recv_by_size, send_with_size
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(bdata: str | bytearray | bytes, key: str | bytearray | bytes, iv: str | bytearray | bytes):
    """
    sends tcp message with AES encryption.
    using send_with_size from tcp_by_size.
    :param bdata: the data to send.
    :param key: the key for the AES encryption.
    :param iv: the iv for the AES encryption.
    :return: nothing
    """
    if not isinstance(bdata, bytes):
        if isinstance(bdata, str):
            bdata = bdata.encode()
        else:
            bdata = bytes(bdata)
    # If the data isn't bytes converts it into bytes
    bdata = pad(bdata, AES.block_size)
    # Adds padding
    if not isinstance(key, bytes):
        if isinstance(key, str):
            key = bytes(key.encode())
        else:
            key = bytes(key)
    # If the key isn't bytes converts it into bytes
    if not isinstance(iv, bytes):
        if isinstance(iv, str):
            iv = bytes(iv.encode())
        else:
            iv = bytes(iv)
    # If the iv isn't bytes converts it into bytes
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        print('Wrong key length.\n'
              'For AES-128 use a 16 byte key\n'
              'For AES-192 use a 24 byte key\n'
              'For AES-256 use a 32 byte key\n')
    #checks key length
    if len(iv) != 16:
        print('Wrong iv length')
    #checks iv length
    AES_encrypt = AES.new(key, AES.MODE_CBC, iv)
    #creates the AES encryption object
    cypher_data = AES_encrypt.encrypt(bdata)
    # encrypting the bdata
    return cypher_data


def aes_decrypt(encrypted_bdata, key: str | bytearray | bytes, iv: str | bytearray | bytes) -> bytes:
    """
    receives data and decrypts it using AES
    :param encrypted_bdata: cypher
    :param key: the key that the message was encrypted with
    :param iv: the iv that the message was encrypted with
    :return: the decrypted message
    """
    # Receives the message
    if not isinstance(key, bytes):
        if isinstance(key, str):
            key = bytes(key.encode())
        else:
            key = bytes(key)
    # If the key isn't bytes converts it into bytes
    if not isinstance(iv, bytes):
        if isinstance(iv, str):
            iv = bytes(iv.encode())
        else:
            iv = bytes(iv)
    # If the iv isn't bytes converts it into bytes
    AES_decrypt = AES.new(key, AES.MODE_CBC, iv)
    # creates the AES encryption object
    original_bdata = AES_decrypt.decrypt(encrypted_bdata)
    # decrypts the encrypted data
    original_bdata = unpad(original_bdata, AES.block_size)
    return original_bdata
