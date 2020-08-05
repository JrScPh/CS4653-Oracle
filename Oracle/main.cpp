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

BYTE fun_434860(BYTE param_1)
{
  int iVar1;
  BYTE *puVar2;
  BYTE local_dc[54];

  iVar1 = 0x36;
  puVar2 = local_dc;

  while (iVar1 != 0) {
    iVar1 -= 1; // = iVar1 + -1

    *puVar2 = 0xcccccccc;

    puVar2 += 1; // puVar2 + 1
  }

  return (BYTE)(param_1 * '\x10' + (char)((int)(BYTE)param_1 >> 4));
}


BYTE fun_4348c0(BYTE param_1, BYTE param_2)
{
  int iVar1;
  BYTE *puVar2;
  BYTE local_dc[49];
  BYTE local_15;
  BYTE local_9;

  iVar1 = 0x36;
  puVar2 = local_dc;

  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;

    *puVar2 = 0xcccccccc;

    puVar2 = puVar2 + 1;
  }

  if (param_2 == '\x01')
  {
    local_9 = (BYTE)((int)(BYTE)param_1 / 2) | param_1 << 7;
  }
  else
  {
    local_15 = param_1 & 0x80;
    if (local_15 != 0) {
      local_15 = 1;
    }
    local_9 = param_1 << 1 | local_15;
  }
  return (BYTE) local_9;
}

BYTE fun_434980(BYTE param_1)

{
  int iVar1;
  BYTE *puVar2;
  BYTE local_f4[60];

  iVar1 = 0x3c;
  puVar2 = local_f4;

  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;

    *puVar2 = 0xcccccccc;

    puVar2 = puVar2 + 1;
  }

  return (BYTE)((BYTE)(((BYTE)param_1 & 0x30) << 2) | (BYTE)((int)((BYTE)param_1 & 0xc0) >>2)
                      | (byte)(((BYTE)param_1 & 3) << 2) | (BYTE)((int)(BYTE)param_1 >> 2) & 3);
}

// this function is actually the answer - when completed!
int encryptFile(FILE *fptr, char *password)
{
	char *buffer;
	BYTE pwdHash[32];

	FILE *fptrOut;
	DWORD passwordLength, filesize, i;
	int resulti, pwdHashIndx;

	// Added by Shane
	int local_170;
	BYTE uVar3;
	BYTE local_129;
	BYTE local_138;

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

    local_170 = 0;
    while(local_170 < filesize - (passwordLength + 1))
    {
        uVar3 = fun_434980(*(BYTE *)((int)buffer + local_170));

        *(byte *)((int) buffer + local_170) = (char) uVar3;

        if((local_170 && 4) == 0)
        {
            // XOR the current buffer char with var_134 (related to pwdHashIndx?) and replace it with the result
            // TODO: figure out the value of var_134
            *(byte *)((int)buffer + local_170) = *(byte *)((int)buffer + local_170) ^ var_134;
        }
        else
        {
            // XOR the current buffer char with var_125 (related to pwdHashIndx?) and replace it with the result
            // TODO: figure out the value of var_125
            *(byte *)((int)buffer + local_170) = *(byte *)((int)buffer + local_170) ^ var_125;
        }

        uVar3 = fun_4348c0(*(buffer + local_170), '\0');


        *(byte *)((int) buffer + local_170) = (char) uVar3;

        uVar3 = fun_434860(*(byte *)((int)buffer + local_170));

        *(byte *)((int) buffer + local_170) = (char) uVar3;

        local_170 += 1;
    }


	fptrOut = fopen("encrypted.txt", "wb+");
	if(fptrOut == NULL)
	{
		fprintf(stderr, "Error - Could not open output file.\n\n");
		free(buffer);
		return -1;
	}

    fwrite(buffer, 1, filesize - passwordLength, fptrOut);

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
	char inputFile[] = "decrypted.txt";

	if(argc < 3)
	{
		fprintf(stderr, "\n\nTo encrypt, you must enter the file to encrypt followed by the password.\n\n");
		fprintf(stderr, "%s filename password\n\n", argv[0]);
		exit(0);
	}

	fptr = openInputFile(argv[1]);
	encryptFile(fptr, argv[2]);
	fclose(fptr);
    return 0;
	fptr = openInputFile(inputFile);

	// decryptFile(fptr);
	fclose(fptr);
	return 0;
} // main
