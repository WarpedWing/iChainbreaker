import argparse
import os
import sqlite3 as lite
import string
import sys
import uuid
from binascii import hexlify
from ctypes import POINTER, LittleEndianStructure, c_char_p, c_uint32, cast, sizeof
from getpass import getpass

from Crypto.Cipher import AES
from hexdump import hexdump

from blobparser import BlobParser

# from crypto.gcm import gcm_decrypt
from crypto.aeswrap import AESUnwrap
from exportDB import ExporySQLiteDB
from itemv7 import ItemV7
from keybag import Keybag


class _EncryptedBlobHeader(LittleEndianStructure):
    _fields_ = [('version', c_uint32), ('clas', c_uint32), ('length', c_uint32)]


def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents


def GetTableFullName(table):
    if table == 'genp':
        return 'Generic Password'
    elif table == 'inet':
        return 'Internet Password'
    elif table == 'cert':
        return 'Certification'
    elif table == 'keys':
        return 'Keys'
    else:
        return 'Unknown'


def main():
    parser = argparse.ArgumentParser(
        description='Tool for Local Items (iCloud) Keychain Analysis by @n0fate'
    )
    parser.add_argument(
        '-p',
        '--path',
        nargs=1,
        help='iCloud Keychain Path(~/Library/Keychains/[UUID]/)',
        required=True,
    )
    parser.add_argument(
        '-k',
        '--key',
        help='User Password (optional, will ask via stdin if not provided)',
        required=False,
    )
    parser.add_argument(
        '-x',
        '--exportfile',
        nargs=1,
        help='Write a decrypted contents to SQLite file (optional)',
        required=False,
    )
    parser.add_argument('-v', '--version', nargs=1, help='macOS version(ex. 10.13)', required=True)
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output (raw keybag structure)',
        required=False,
    )

    args = parser.parse_args()

    Pathoficloudkeychain = args.path[0]

    if os.path.isdir(Pathoficloudkeychain) is False:
        print('[!] Path is not directory')
        parser.print_help()
        sys.exit(1)

    if os.path.exists(Pathoficloudkeychain) is False:
        print('[!] Path is not exists')
        parser.print_help()
        sys.exit(1)

    # version check
    import re

    gcmIV = b''
    re1 = '(10)'  # Integer Number 1
    re2 = '(\\.)'  # Any Single Character 1
    re3 = '(\\d+)'  # Integer Number 2

    rg = re.compile(re1 + re2 + re3, re.IGNORECASE | re.DOTALL)
    m = rg.match(args.version[0])
    if m:
        minorver = int(m.group(3))
        if minorver >= 12:
            # Security-57740.51.3/OSX/sec/securityd/SecDbKeychainItem.c:97
            #
            # // echo "keychainblobstaticiv" | openssl dgst -sha256 | cut -c1-24 | xargs -I {} echo "0x{}" | xxd -r | xxd -p  -i
            # static const uint8_t gcmIV[kIVSizeAESGCM] = {
            #     0x1e, 0xa0, 0x5c, 0xa9, 0x98, 0x2e, 0x87, 0xdc, 0xf1, 0x45, 0xe8, 0x24
            # };
            gcmIV = b'\x1e\xa0\x5c\xa9\x98\x2e\x87\xdc\xf1\x45\xe8\x24'
        else:
            gcmIV = b''
    else:
        print('[!] Invalid version')
        parser.print_help()
        sys.exit(1)

    export = 0
    if args.exportfile is not None:
        if os.path.exists(args.exportfile[0]):
            print('[*] Export DB File is exists.')
            sys.exit(1)
        export = 1

    # Start to analysis
    print('Tool for iCloud Keychain Analysis by @n0fate')

    MachineUUID = os.path.basename(os.path.normpath(Pathoficloudkeychain))
    PathofKeybag = os.path.join(Pathoficloudkeychain, 'user.kb')
    PathofKeychain = os.path.join(Pathoficloudkeychain, 'keychain-2.db')

    print(f'[*] macOS version is {args.version[0]}')
    print(f'[*] UUID : {MachineUUID}')
    print(f'[*] Keybag : {PathofKeybag}')
    print(f'[*] iCloud Keychain File : {PathofKeychain}')

    if os.path.exists(PathofKeybag) is False or os.path.exists(PathofKeychain) is False:
        print('[!] Can not find KeyBag or iCloud Keychain File')
        sys.exit(1)

    keybag = Keybag(PathofKeybag)
    keybag.load_keybag_header()
    keybag.debug_print_header()

    if args.debug:
        keybag.debug_dump_raw_header()

    # Try directory UUID first (pre-Sequoia behavior)
    devicekey = keybag.device_key_init(uuid.UUID(MachineUUID).bytes)
    print(f'[*] Device key (from directory UUID): {hexlify(devicekey)}')

    bresult = keybag.device_key_validation()

    if bresult is False:
        # On Sequoia+, try the keybag's internal UUID instead
        keybag_uuid = uuid.UUID(bytes=bytes(bytearray(keybag.keybag['uuid'])))
        print(
            f'[!] Device Key validation failed with directory UUID. '
            f'Trying keybag internal UUID: {keybag_uuid}'
        )
        devicekey = keybag.device_key_init(keybag_uuid.bytes)
        print(f'[*] Device key (from keybag UUID): {hexlify(devicekey)}')

        bresult = keybag.device_key_validation()
        if bresult is False:
            print('[!] Device Key validation : Failed with both UUIDs')
            print('[!] This may indicate:')
            print('    - Incorrect keychain directory')
            print('    - Corrupted keybag file')
            print('    - Unsupported macOS version')
            return
        else:
            print('[*] Device Key validation : Pass (using keybag UUID)')
    else:
        print('[*] Device Key validation : Pass (using directory UUID)')

    passcodekey = keybag.generatepasscodekey(args.key if args.key else getpass())

    print(f'[*] The passcode key : {hexlify(passcodekey)}')

    keybag.Decryption()

    con = lite.connect(PathofKeychain)
    con.text_factory = str
    cur = con.cursor()

    tablelist = ['genp', 'inet', 'cert', 'keys']

    # Summary counters per table
    summary = {
        t: {
            'total': 0,
            'decrypted': 0,
            'exported': 0,
            'missing_class_key': 0,
            'missing_metadatakey': 0,
            'unwrap_fail': 0,
            'gcm_mac_fail': 0,
            'empty_decrypt': 0,
        }
        for t in tablelist
    }

    if export:
        # Create DB
        exportDB = ExporySQLiteDB()
        exportDB.createDB(args.exportfile[0])
        print(f'[*] Export DB Name : {args.exportfile[0]}')
    else:
        exportDB = None

    for tablename in tablelist:
        if export != 1:
            print(f'[+] Table Name : {GetTableFullName(tablename)}')
        try:
            # Also fetch rowid so we can identify failures
            cur.execute(f"SELECT rowid, data FROM {tablename}")
        except lite.OperationalError:
            continue

        if export:
            # Get Table Schema
            sql = con.execute(f"pragma table_info('{tablename}')").fetchall()

            # Create a table
            exportDB.createTable(tablename, sql)

        for rowid, data in cur:
            record = None
            decrypted = None
            current_label = 'unknown'
            summary[tablename]['total'] += 1
            encblobheader = _memcpy(data[: sizeof(_EncryptedBlobHeader)], _EncryptedBlobHeader)

            if encblobheader.version == 7:
                item = ItemV7(data)

                key = keybag.GetKeybyClass(item.keyclass)
                if not key:
                    summary[tablename]['missing_class_key'] += 1
                    print(
                        f"[!] Missing class key for keyclass {item.keyclass}; skipping item (table={tablename}, rowid={rowid}, label={current_label})."
                    )
                    continue

                # Decrypt metadata first to extract label early
                metadatakey_row = con.execute(
                    'select data from metadatakeys where keyclass=?', (item.keyclass,)
                ).fetchone()
                if not metadatakey_row:
                    summary[tablename]['missing_metadatakey'] += 1
                    print(
                        f"[!] No metadata key found for keyclass {item.keyclass}; skipping item (table={tablename}, rowid={rowid}, label={current_label})."
                    )
                    continue
                metadatakey = metadatakey_row[0]

                unwrapped_metadata_key = AESUnwrap(key, metadatakey)
                if not unwrapped_metadata_key:
                    summary[tablename]['unwrap_fail'] += 1
                    print(
                        f"[!] Failed to unwrap metadata key for keyclass {item.keyclass}; skipping item (table={tablename}, rowid={rowid}, label={current_label})."
                    )
                    continue

                metadata = item.decrypt_metadata(unwrapped_metadata_key)
                # Extract label from metadata when possible
                blobparse = BlobParser()
                md_record = blobparse.ParseIt(metadata, tablename, export)
                current_label = (
                    md_record.get('labl', 'unknown')
                    if export == 1
                    else md_record.get('Label', 'unknown')
                )

                # Attempt to decrypt secret after we have metadata
                try:
                    decrypted = item.decrypt_secret_data(key)
                except Exception:
                    decrypted = None

                if export == 0:
                    print('[+] DECRYPTED METADATA')
                    handle_decrypted(metadata, export, tablename)
                    if decrypted is not None:
                        print('[+] DECRYPTED SECRET INFO')
                        handle_decrypted(decrypted, export, tablename)
                else:  # export == 1
                    record = md_record
                    # Merge secret record (if decrypted)
                    if decrypted is not None:
                        record.update(blobparse.ParseIt(decrypted, tablename, export))

            else:
                encblobheader.clas &= 0x0F

                wrappedkey = data[
                    sizeof(_EncryptedBlobHeader) : sizeof(_EncryptedBlobHeader)
                    + encblobheader.length
                ]
                if encblobheader.clas == 11:
                    encrypted_data = data[sizeof(_EncryptedBlobHeader) + encblobheader.length :]
                    auth_tag = data[-20:-4]
                else:
                    encrypted_data = data[sizeof(_EncryptedBlobHeader) + encblobheader.length : -16]
                    auth_tag = data[-16:]

                key = keybag.GetKeybyClass(encblobheader.clas)

                if not key:
                    summary[tablename]['missing_class_key'] += 1
                    print(
                        f"[!] Could not find any key at class {encblobheader.clas} (table={tablename}, rowid={rowid}, label=unknown)"
                    )
                    continue

                unwrappedkey = AESUnwrap(key, wrappedkey)

                if unwrappedkey is None:
                    summary[tablename]['unwrap_fail'] += 1
                    print(
                        f"[!] Failed to unwrap class {encblobheader.clas} key; skipping (table={tablename}, rowid={rowid}, label=unknown)"
                    )
                    continue

                gcm = AES.new(unwrappedkey, AES.MODE_GCM, gcmIV)
                # Apple uses the EncryptedBlobHeader as AAD; include it for MAC to pass
                try:
                    gcm.update(data[: sizeof(_EncryptedBlobHeader)])
                except Exception:
                    pass
                try:
                    decrypted = gcm.decrypt_and_verify(encrypted_data, auth_tag)
                except ValueError:
                    summary[tablename]['gcm_mac_fail'] += 1
                    print(
                        f"[!] GCM MAC check failed for class {encblobheader.clas}; skipping record (table={tablename}, rowid={rowid}, label=unknown)."
                    )
                    continue

                # decrypted = gcm_decrypt(unwrappedkey, gcmIV, encrypted_data, data[:sizeof(_EncryptedBlobHeader)], auth_tag)

                if len(decrypted) == 0:
                    summary[tablename]['empty_decrypt'] += 1
                    if export == 0:
                        print(
                            f"[!] Empty decrypted data; skipping (table={tablename}, rowid={rowid}, label=unknown)"
                        )
                    continue

                if export == 0:
                    print('[+] DECRYPTED INFO')

                handle_decrypted(decrypted, export, tablename)
                blobparse = BlobParser()
                record = blobparse.ParseIt(decrypted, tablename, export)

            if export == 1 and record is not None:
                export_Database(record, export, exportDB, tablename)
                summary[tablename]['exported'] += 1
                summary[tablename]['decrypted'] += 1
            elif export == 0 and decrypted is not None:
                summary[tablename]['decrypted'] += 1

    if export:
        exportDB.commit()
        exportDB.close()

    cur.close()
    con.close()

    # Print summary
    print('[*] Summary')
    total_all = 0
    dec_all = 0
    exp_all = 0
    for t in tablelist:
        s = summary[t]
        total_all += s['total']
        dec_all += s['decrypted']
        exp_all += s['exported']
        print(
            f" [-] {GetTableFullName(t)}: total={s['total']}, decrypted={s['decrypted']}, "
            f"exported={s['exported']}, missing_class_key={s['missing_class_key']}, "
            f"missing_metadatakey={s['missing_metadatakey']}, unwrap_fail={s['unwrap_fail']}, "
            f"mac_fail={s['gcm_mac_fail']}, empty_decrypt={s['empty_decrypt']}"
        )
    print(f' [-] Overall: total={total_all}, decrypted={dec_all}, exported={exp_all}')


def handle_decrypted(decrypted, export, tablename):
    blobparse = BlobParser()
    record = blobparse.ParseIt(decrypted, tablename, export)
    for k, v in record.items():
        if k == 'Data':
            # Prefer plain text if the secret looks like UTF-8 text; otherwise hexdump
            if isinstance(v, (bytes, bytearray, memoryview)):
                raw = bytes(v)

                def _looks_text(b: bytes) -> bool:
                    if not b:
                        return False
                    try:
                        s = b.decode('utf-8')
                    except UnicodeDecodeError:
                        return False
                    # Allow printable chars and common whitespace
                    return all(ch.isprintable() or ch in '\r\n\t' for ch in s)

                if _looks_text(raw):
                    try:
                        text = raw.decode('utf-8')
                    except Exception:
                        text = raw.decode('latin1', errors='replace')
                    print(' [-]', k, ':', text)
                else:
                    print(' [-]', k)
                    hexdump(raw)
            else:
                try:
                    text = v if isinstance(v, str) else str(v)
                except Exception:
                    text = repr(v)
                print(' [-]', k, ':', text)
        elif k == 'Type' and GetTableFullName(tablename) == 'Keys':
            print(' [-]', k, ':', blobparse.GetKeyType(int(v)))
        else:
            printable = str(v)
            if not all(c in string.printable for c in printable):
                printable = repr(v)
            print(' [-]', k, ':', printable)
    print('')


def export_Database(record, export, exportDB, tablename):
    record_lst = []
    for k, v in record.items():
        if k != 'SecAccessControl':
            if k != 'TamperCheck':
                record_lst.append([k, v])
    if len(record_lst) != 0:
        exportDB.insertData(tablename, record_lst)


if __name__ == "__main__":
    main()
