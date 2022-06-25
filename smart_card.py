import pkcs11
import ssl
from pkcs11.util.rsa import encode_rsa_public_key
from os import path



class SmartCard:
    """Klasa obsługująca podpisywanie plików"""

    def __init__(self, pkcs_path :str) -> None:
        try:
            self.__lib = pkcs11.lib(pkcs_path) # inicjuje biblioteke
        except:
            raise RuntimeError('Blad inicjalizacji biblioteki pkcs.\n Sprawdź czy aby na pewno ścieżka do pliku pkcs11 jest poprawna.\n Jeśli nie - zaktualizuj ją przy pomocy --pkcs-path')
    
    def load_card(self) -> bool:
        """Wczytuje karte jesli jest w czytniku. Zwraca False jeśli nie widzi czytnika"""
        
        # Szukam tokenu czytnika Certum
        self.__token = None
        for slot in self.__lib.get_slots():
            self.__token = slot.get_token()
            if self.__token.label == 'profil standardowy':
                return True
        return False

    def sign_file(self, path :str, pin :str) -> bytes:
        """
        Podpisuje plik i zwraca sygnature
        path (str) - lokalizacja pliku do podpisania
        """

        if not self.load_card():
            raise EnvironmentError('Card reader not found')

        # Wczytuje plik
        file = open(path, 'rb')
        data = file.read()
        file.close()
        
        token = self.__token
        with token.open(user_pin=pin) as session:

            # Pobieram obiekt reprezentujcy klucz prywatny na smart card
            private = next(session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY, 
            }))

            # Zlecam karcie podpisanie danych
            signature = private.sign(data)

            # Zwracam sygnature
            return signature
    
    def export_public_key(self, pin :str) -> str:
        """Zwraca klucz publiczny ze smart card w formacie pem"""

        if not self.load_card():
            raise EnvironmentError('Card not found')

        with self.__token.open(user_pin=pin) as session:

            # Pobieram obiekt reprezentujcy klucz publiczny na smart card
            public = next(session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY, 
            }))

            # Exportuje klucz z karty do formatu der
            exported = pkcs11.util.rsa.encode_rsa_public_key(public)

            # Konwertuje klucz do pem
            pem_cert = ssl.DER_cert_to_PEM_cert(exported)
            return pem_cert
