import pkcs11
from os.path import exists, splitext

from smart_card import SmartCard

from Cryptodome.Hash import SHA512
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.PublicKey import RSA



class Certificate:
    file = None

    def __init__(
        self,
        validated_file_path: str, 
        certificate_file_path: str=None
    ):
        '''
        validated_file_path (str) - ścieżka do pliku oryginalnego
        certificate_file_path (str) - (opcjonalne) ścieżka do pliku certyfikatu, jeśli nie zostanie podana
                                      program automatycznie wybierze nazwe pliku + ext
        '''
        if not exists(validated_file_path):
            print('Plik nie istnieje')
            exit()

        if certificate_file_path is not None:
            self.certificate_file_path = certificate_file_path
        else:
            self.certificate_file_path = f'{splitext(validated_file_path)[0]}.sacproj'
        self.validated_file_path = validated_file_path

    def create_certificate_file(
        self, 
        pin: str, 
        pkcs_path: str = '/opt/proCertumCardManager/sc30pkcs11-3.0.5.65-MS.so'
    ) -> bool:
        '''
        Podpisuje oraz tworzy plik certyfikatu w self.certificate_file_path
        pin (str) - kod pin do karty
        pkcs_path (str) - (opcjonalny) ścieżka do biblioteki PKCS11
        '''

        try:
            smart_card = SmartCard(pkcs_path)

        except RuntimeError as e:
            print(e)
            return False


        try:
            signature = smart_card.sign_file(path=self.validated_file_path, pin=str(pin))

        except EnvironmentError as e:
            print('Nie znaleziono czytnika')

        except pkcs11.exceptions.PinIncorrect:
            print('Zly pin')

        except pkcs11.exceptions.TokenNotPresent:
            print('Brak karty w czytniku')

        except pkcs11.exceptions.PinLocked:
            print('Karta zablokowana')

        except BaseException:
            print('Wystapil blad')
        
        else:
            decision = 't'
            if exists(self.certificate_file_path):
                decision = input(f'Plik "{self.certificate_file_path}" juz istnieje. Nadpisac? (t/n) ')
            
            if decision.lower() == 't':
                try:
                    with open(self.certificate_file_path, 'wb') as file:
                        file.write(signature)

                except Exception:
                    print('Blad zapisu sygnatury na dysku')

                else:
                    file.close()
                    return True
            else:
                print('Podpisywanie zostalo anulowane')

        
        return False


    def verify_signature(self, public_key_path :str) -> bool:
        """
        Weryfikuje podpis cyfrowy
        file_path (str) - podpisany plik
        signature (bytes) - podpis
        public_key (str) - plik z kluczem publicznym
        """
        # Wczytuje certyfikat
        file = open(self.certificate_file_path, 'rb')
        signature = file.read()
        file.close()

        # Wczytuje plik oryginalny
        file = open(self.validated_file_path, 'rb')
        data = file.read()
        file.close()

        # Licze hash SHA512 z pliku
        hash = SHA512.new()
        hash.update(data)
        
        # Wczytuje klucz publiczny z pliku
        file = open(public_key_path, 'r')
        public_key = file.read()
        file.close()

        # Szykuje narzedzia weryfikujace
        public_key = RSA.importKey(public_key)
        verifier = PKCS1_v1_5.new(public_key)

        # Weryfikuje podpis
        verified = verifier.verify(hash, signature)
        return verified

def sign(file_path: str, pin: str, pkcs_path: str):
    created_certificate = Certificate(file_path)
    res = created_certificate.create_certificate_file(pin, pkcs_path)

    if res: print("Pomyslnie podpisano plik")

def verify(file_path: str, cert_file_path: str, public_key_path: str):
    certificate = Certificate(file_path, cert_file_path)
    res = certificate.verify_signature(public_key_path)

    if res: print('Podpis jest poprawny')
    else: print('Popdpis jest niepoprawny')

def extract(
        pin: str, 
        out_file: str, 
        pkcs_path: str = '/opt/proCertumCardManager/sc30pkcs11-3.0.5.65-MS.so'
    ):
    '''
    Łączy się z kartą a następnie pobiera klucz publiczny
    pin (str) - pin do smart karty
    out_file (str) - plik do które zapisany zostanie
    pkcs_path (str) - (opcjonalny) ścieżka do biblioteki PKCS11 
    '''
    try:
        smart_card = SmartCard(pkcs_path)

    except RuntimeError as e:
        print(e)

    try:
        pub = smart_card.export_public_key(pin)

    except EnvironmentError as e:
        print('Nie znaleziono czytnika')

    except pkcs11.exceptions.PinIncorrect:
        print('Zly pin')

    except pkcs11.exceptions.TokenNotPresent:
        print('Brak karty w czytniku')

    except pkcs11.exceptions.PinLocked:
        print('Karta zablokowana')

    except BaseException:
        print('Wystapil blad')

    else:
        file = open(out_file, 'w')
        file.write(pub)
        file.close()
