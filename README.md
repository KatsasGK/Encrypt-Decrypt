# Encrypt-Decrypt
A simple script to Encrypt and Decrypt messages.

---USAGE:---
1. Make sure you have the following dependencies installed: cryptography, loguru, and argparse. You can install them by running the command pip install cryptography loguru argparse
2. Download the script and save it to a location on your computer.
3. Open a command prompt or terminal and navigate to the location where you saved the script.
4. Run the script by typing python scriptname.py followed by the arguments.


The script takes three arguments:
-p or --password : this is the password that will be used to encrypt and decrypt the message.
-m or --message : this is the message that you want to encrypt or decrypt.
-a or --action : this is the action that you want to perform, either 'encrypt' or 'decrypt'


For the first time you run the script you must provide the password argument, the script will use it to generate the key file that will be used to encrypt and decrypt the messages.
For example, if you want to encrypt the message "Hello World" with the password "mysecretpassword", you would run the following command:
Copy code
python scriptname.py -p mysecretpassword -m "Hello World" -a encrypt
The script will then encrypt the message and print the encrypted message to the screen.
To decrypt the message, you would run the following command:
Copy code
python scriptname.py -p mysecretpassword -m "encrypted_message" -a decrypt
The script will then decrypt the message and print the decrypted message to the screen.
