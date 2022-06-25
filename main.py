import argparse
from cert import sign, verify, extract

def load_path() -> str:
    try:
            f = open('pkcs_path.config', 'r')
            
    except FileNotFoundError:
        print('Brak pliku konfiguracyjnego które zawiera ścieżę do biblioteki pkcs11. \nPodaj ścieżkę do pliku przy pomocy przełącznika --pkcs_path. \nW przypadku opgramowania Certum znajduje się on w /opt/proCertumCardManager/sc30pkcs11-x.x.x.xx-MS.so')
        exit()

    pkcs_path = f.read()
    f.close()

    return pkcs_path

def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument('-in', '--original', action='store', help="Path to the original file", metavar=('file'))
    parser.add_argument('-s', '--sign', action='store', help='Sign the file, requires PIN and original file [-in]', metavar=('pin'))
    parser.add_argument('-v', '--verify', action='store', help='Verify the signature, requires the public key and original file [-in]', nargs=2, metavar=('public_key', 'cert'))
    parser.add_argument('-e', '--extract', action='store', help='Extract the public key stored on the smart card', nargs=2, metavar=('pin', 'out_file'))
    parser.add_argument('--pkcs-path', action='store', help='Update the path to the pkcs11 library', metavar='pkcs_path')
    parser.add_argument('--print-path', action='store_true', help='Print pkcs11 library path currently loaded in config')
    
    args = vars(parser.parse_args())

    if args['print_path']:
        print(load_path())
        exit()
    elif args['pkcs_path'] is None:
        pkcs_path = load_path()
    else:
        pkcs_path = args['pkcs_path']

        f = open('pkcs_path.config', 'w')
        f.write(pkcs_path)
        exit()

    if args['extract'] is not None:
        extract(args['extract'][0], args['extract'][1], pkcs_path=pkcs_path)
    elif args['original'] is not None:
        if args['sign'] is not None:
            sign(args['original'], args['sign'], pkcs_path=pkcs_path)
        elif args['verify'] is not None:
            verify(args['original'], args['verify'][1], args['verify'][0])
    else: print('Nie podano pliku oryginalnego')


if __name__ == '__main__':
    main()
