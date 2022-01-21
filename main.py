import argparse
import logging
import random
import string
from pathlib import Path
from typing import BinaryIO, Any

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import pad, unpad

ROOT_PATH = Path()
TMP_PATH = ROOT_PATH / 'tmp'

FORMAT = '[%(asctime)s][%(name)s][%(threadName)-10s] - %(levelname)s: %(message)s'


class App:
    __slots__ = ['_file', '_file_path', '_out_path', '_key', '_private_key', '_public_key']

    _file: bytes
    _file_path: Path
    _out_path: Path
    _key: str
    _private_key: RsaKey
    _public_key: RsaKey

    def __init__(self, file_path: Path = Path(), out_path: Path = Path(), flag: bool = True):
        if flag:
            self._file_path = file_path
            self._out_path = out_path
            self._file = self._load_file(self._file_path)
        else:
            pass

    def encrypt(self, public_key_path: Path):
        """
        Method to encrypt a file
        :param public_key_path: Directory of the public key
        :return:
        """
        logging.info(f'Starting encryption for file {self._file_path.name}')
        self._public_key = RSA.import_key(open(public_key_path.resolve(), 'r').read())
        self._generate_key_file()
        self._encrypt_file()

    def decrypt(self, private_key_path: Path, key_file_path: Path):
        """
        Method to decrypt a file
        :param private_key_path: Directory of the private key
        :param key_file_path: Directory of the unique key file
        :return:
        """
        logging.info(f'Starting decryption for file {self._file_path.name}')
        self._private_key = RSA.import_key(open(private_key_path.resolve(), 'r').read())
        self._set_file_key(key_file_path)
        self._decrypt_file()

    def _set_file_key(self, key_path: Path):
        """
        Private method to set the unique key of to decrypt the file.
        :param key_path:
        :return:
        """
        self._decrypt_key_file(key_path)

    def generate_keys(self):
        """
        Method to create the public and private RSA keys
        :return:
        """
        logging.info('Generating public and private keys ...')
        private_key: RsaKey = RSA.generate(1024)
        public_key: RsaKey = private_key.public_key()

        private_pem: str = private_key.exportKey().decode()
        public_pem: str = public_key.exportKey().decode()

        self._write_file(ROOT_PATH / 'private_key.pem', private_pem)
        self._write_file(ROOT_PATH / 'public_key.pem', public_pem)

        logging.info('Public and private keys have been written.')

    def _generate_key_file(self):
        """
        Create a random unique key to be used to encrypt and decrypt the document
        :return:
        """
        letters = string.ascii_lowercase
        self._key = ''.join(random.choice(letters) for i in range(16))
        logging.info(f'{len(self._key)} bytes key file has been created.')
        self._encrypt_key_file()

    def _encrypt_key_file(self):
        """
        Method to encrypt and store the unique key file
        :return:
        """
        logging.debug(f'Current public key {self._public_key}')
        cipher = PKCS1_OAEP.new(key=self._public_key)
        key = cipher.encrypt(self._key.encode())
        key_path = self._out_path / 'file.key'
        self._write_binary_file(key_path, key)
        logging.info(f'Key file has been saved on {key_path}')

    def _encrypt_file(self):
        """
        Method to encrypt the document with AES
        :return:
        """
        IV = b'secretsecretsecr'
        logging.info('Running AES cipher in CBC mode ...')
        aes = AES.new(key=self._key.encode(), mode=AES.MODE_CBC, iv=IV)
        encrypted_data = aes.encrypt(pad(self._file, AES.block_size))
        new_path = self._out_path / f'{self._file_path.name}.encrypted'
        logging.info(f'Encrypted file has been save on {new_path.resolve()}')
        self._write_binary_file(new_path.resolve(), encrypted_data)

    def _decrypt_file(self):
        """
        Method to decrypt the document with AES
        :return:
        """
        IV = b'secretsecretsecr'
        aes = AES.new(key=self._key.encode(), mode=AES.MODE_CBC, iv=IV)
        data = unpad(aes.decrypt(self._file), AES.block_size)
        new_path = self._out_path / f'{self._file_path.name.replace(".encrypted", "")}'
        self._write_binary_file(new_path.resolve(), data)
        logging.info(f'File {new_path.resolve()} has been decrypted successfully.')

    def _decrypt_key_file(self, key_path: Path):
        """
        Method to decrypt the unique key to be use with to encrypt and decrypt the document
        :param key_path: Directory of the unique encrypted key
        :return:
        """
        key = self._load_file(key_path)
        decrypter: PKCS1OAEP_Cipher = PKCS1_OAEP.new(key=self._private_key)
        self._key = decrypter.decrypt(key).decode()
        logging.info('Key file has been decrypted successfully.')

    @staticmethod
    def _write_file(file_path: Path, data: Any):
        """
        Static method to write data in a file
        :param file_path: Directory in which the file will be stored
        :param data: Data to be written in the file
        :return:
        """
        try:
            logging.debug(f'Writing file on {file_path.resolve()}')
            file = open(file_path.resolve(), 'w')
            file.write(data)
            file.close()
        except Exception as error:
            logging.error(error)

    @staticmethod
    def _write_binary_file(file_path: Path, data: bytes):
        """
        Static method to write data bytes in a file
        :param file_path: Directory in which the file will be stored
        :param data: Data to be written in the file in bytes
        :return:
        """
        try:
            logging.debug(f'Writing file on {file_path.resolve()}')
            file = open(file_path.resolve(), 'wb')
            file.write(data)
            file.close()
        except Exception as error:
            logging.error(error)

    @staticmethod
    def _load_file(file_path: Path) -> bytes:
        """
        Static method to read a file in bytes
        :param file_path: Directory of the file to be read
        :return:
        """
        try:
            logging.debug(f'Opening {file_path.resolve()}')
            file: BinaryIO = open(file_path.resolve(), 'rb')
            data: bytes = file.read()
            file.close()
            return data
        except Exception as error:
            logging.error(error)

    def _set_file(self, file_path):
        self._file_path = file_path

    @property
    def file(self):
        return self._file

    @property
    def key(self):
        return self._key

    @property
    def file_path(self):
        return self._file_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='encrypt-sensitive-documents')

    subparser = parser.add_subparsers(dest='command')

    encrypt = subparser.add_parser('encrypt', description='')
    encrypt.add_argument('-f', '--file', action='store', type=str, required=True,
                         help='Path of the file to be encrypted.')
    encrypt.add_argument('-k', '--key', action='store', type=str, required=True, default='public_key.pem',
                         help='Path of the public key to be used to encrypt the AES key.')
    encrypt.add_argument('-o', '--out_dir', action='store', type=str, required=False, default='./tmp',
                         help='Path in witch the encrypted file and the key will be created.')

    decrypt = subparser.add_parser('decrypt', description='')
    decrypt.add_argument('-f', '--file', action='store', type=str, required=True,
                         help='Path of the file to be decrypted.')
    decrypt.add_argument('-k', '--key', action='store', type=str, required=True, default='private_key.pem',
                         help='Path of the private key to be used to decrypt the AES key.')
    decrypt.add_argument('-fk', '--file_key', action='store', type=str, required=True,
                         help='Path of the key to decrypt the file.')
    decrypt.add_argument('-o', '--out_dir', action='store', type=str, required=False, default='./tmp',
                         help='Path in witch the decrypted file will be created.')

    utils = subparser.add_parser('generate_keys', description='')
    utils.add_argument('-p', '--path', action='store', type=str, required=True,
                       help='Path to store the public and private keys.')

    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')

    OPTIONS = parser.parse_args()

    if OPTIONS.verbose:
        logging.basicConfig(level=logging.DEBUG, format=FORMAT)
    else:
        logging.basicConfig(level=logging.INFO, format=FORMAT)

    if OPTIONS.command == 'encrypt':
        _file_path = Path(OPTIONS.file)
        _key_path = Path(OPTIONS.key)
        _out_path = Path(OPTIONS.out_dir)

        logging.debug(_file_path.resolve())
        logging.debug(_key_path.resolve())
        logging.debug(_out_path.resolve())

        app = App(file_path=_file_path, out_path=_out_path)
        app.encrypt(_key_path)
    elif OPTIONS.command == 'decrypt':
        _file_path = Path(OPTIONS.file)
        _key_path = Path(OPTIONS.key)
        _file_key_path = Path(OPTIONS.file_key)
        _out_path = Path(OPTIONS.out_dir)

        logging.debug(_file_path.resolve())
        logging.debug(_key_path.resolve())
        logging.debug(_file_key_path.resolve())
        logging.debug(_out_path.resolve())

        app = App(file_path=_file_path, out_path=_out_path)
        app.decrypt(_key_path, _file_key_path)
    elif OPTIONS.command == 'generate_keys':
        app = App(flag=True)
        app.generate_keys()
