Obfuscate.c viene usato per cifrare le stringhe in un qualunque programma C.
L'offuscamento avviene passando la stringa al programma:

./obfuscate "system"
unsigned char obf_string[] = "\xd6\x07\xd7\xab\xb1\xab\xae\xbd\xc5";
Deobfuscated string: "system"

Che torna la stringa offuscata in C e stampa il risultato della decifratura per
assicurarsi che la cifratura sia andata a buon fine.

Nel codice dove si vogliono deoffuscare le stringhe basta includere il metodo
deobfuscate() e richiamarlo quando si vuole la stringa:

deobfuscate(obf_string)

non c'e' bisogno di liberare alcun puntatore. A causa della struttura della
stringa offuscata, non e' possibile offuscare stringhe piu' lunghe di 255 caratteri.