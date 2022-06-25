# SmartSigning

Projekt SAC

użycie: main.py [-h] [-in file] [-s pin] [-v public_key cert] [-e pin out_file] [--pkcs-path]

argumenty:

  -h, --help            
  
   ```wypisz wiadomość help```

  -in file, --original file

   ```ścieżka do oryginalnego pliku```

  -s pin, --sign pin    

   ```podpisz plik, wymaga podania PINu oraz ścieżki do oryginalnego pliku [-in]```

  -v public_key cert, --verify public_key cert

   ```zweryfikuj podpis, wymaga podania klucza publicznego oraz ścieżki do oryginalnego pliku [-in]```

  -e pin out_file, --extract pin out_file

   ```pobierz klucz publiczny przechowywany na karcie```

  --pkcs-path pkcs_path

   ```podaj ścieżkę (domyślnie = /opt/proCertumCardManager/sc30pkcs11-3.0.5.65-MS.so)```
                    

Źródła:

https://pyscard.sourceforge.io/user-guide.html

https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands

https://pyscard.sourceforge.io/epydoc

https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
