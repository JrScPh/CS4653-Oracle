// Main.cpp
//
// This program is being used for the 2016_08 CS4953 REverse Engineering Project
// It encrypts or decrypts the input file based on the password
//
// The students are given an encrypted file that has the password embedded. The program, given an input file
// extracts the password and decrypts the file.
//
// The task is to create the code to encrypt an arbitrary file, so that this specific decryption program succeeds.
//

#include <windows.h>
#include <stdio.h>
#include <io.h>
#include "SHA-256.h"

int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);

// this function is actually the answer - when completed!
int encryptFile(FILE *fptr, char *password, char *filename)
{
	char *buffer;
	BYTE pwdHash[32];

	FILE *fptrOut;
	DWORD passwordLength, bufferLength, filesize, i;
	int resulti, pwdHashIndx;

    i = 0;

	filesize = _filelength(_fileno(fptr));
	if(filesize > 0x100000)	// 1 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	passwordLength = (size_t) strlen(password);

	if(passwordLength == 0 || passwordLength >= 256)
	{
		fprintf(stderr, "Error - Password is too long!\n\n");
		return -1;
	}

	resulti = sha256(NULL, password, passwordLength, pwdHash);

	if(resulti != 0)
	{
		fprintf(stderr, "Error - Password not hashed correctly.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *) malloc(filesize);
	if(buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", (int)filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptr);	// should read entire file

    // TODO: encrypt the plaintext using sha256 and pwdHash

    bufferLength = (size_t) strlen(buffer);
    printf("Password is: %s\n", password);
    printf("\nBuffer is: %s\n", buffer);
    printf("\npwdHash before exec sha256 with buffer: %s\n", pwdHash);

    resulti = sha256(filename, buffer, bufferLength, pwdHash);
    if(resulti != 0)
    {
        fprintf(stderr, "Error - File not hashed correctly.\n\n");
        return -1;
    }

    printf("\npwdHash after exec sha256 with buffer: %s\n", pwdHash);
    printf("\nBuffer is: %s\n", buffer);

	fptrOut = fopen("encrypted.txt", "wb+");
	if(fptrOut == NULL)
	{
		fprintf(stderr, "Error - Could not open output file.\n\n");
		free(buffer);
		return -1;
	}

    // TODO: write encrypted message to encryption.txt

	fclose(fptrOut);
	return 0;
} // encryptFile


FILE *openInputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "rb");
	if(fptr == NULL)
	{
		fprintf(stderr, "Error - Could not input file %s!\n\n", filename);
		exit(-1);
	}

	return fptr;
} // openInputFile

int main(int argc, char *argv[])
{
	FILE *fptr;
	char inputFile[] = "encrypted.txt";

	if(argc < 3)
	{
		fprintf(stderr, "\n\nTo encrypt, you must enter the file to encrypt followed by the password.\n\n");
		fprintf(stderr, "%s filename password\n\n", argv[0]);
		exit(0);
	}

	fptr = openInputFile(argv[1]);
	encryptFile(fptr, argv[2], argv[1]);
	fclose(fptr);
    return 0;
	fptr = openInputFile(inputFile);

	// decryptFile(fptr);
	fclose(fptr);
	return 0;
} // main
