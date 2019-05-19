#include <stdio.h>
#include <stdint.h>

#include "AES.h"

// �������16��������
void printHex(uint8_t* ptr, 
	int len, 
	char* tag) 
{
	printf("%s\ndata[%d]: ", tag, len);

	for (int i = 0; i < len; ++i) 
	{
		printf("%.2X ", *ptr++);
	}

	printf("\n");

	return;
}



int main() {

	// case 1
	const uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	const uint8_t pt[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	uint8_t ct[16] = { 0 };     // �ⲿ������������ڴ棬���ڼ��ܺ������
	uint8_t plain[16] = { 0 };  // �ⲿ������������ڴ棬���ڽ��ܺ������

	aesEncrypt(key, 16, pt, ct, 16); // ����

	printHex(pt, 16, "plain data:"); // ��ӡ��ʼ��������

	printf("expect cipher:\n39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32\n");  // �������ܺ����������

	printHex(ct, 16, "after encryption:");  // ��ӡ���ܺ������

	aesDecrypt(key, 16, ct, plain, 16);       // ����

	printHex(plain, 16, "after decryption:"); // ��ӡ���ܺ����������

	// case 2
	// 16�ֽ��ַ�����ʽ��Կ
	const uint8_t key2[] = "1234567890123456";

	// 32�ֽڳ����ַ�������
	const uint8_t* data = (uint8_t*)"abcdefghijklmnopqrstuvwxyz123456";
	uint8_t ct2[32] = { 0 };    //�ⲿ������������ڴ棬���ڴ�ż��ܺ�����
	uint8_t plain2[32] = { 0 }; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����
	//����32�ֽ�����
	aesEncrypt(key2, 16, data, ct2, 32);

	printf("\nplain text:\n%s\n", data);
	printf("expect ciphertext:\nfcad715bd73b5cb0488f840f3bad7889\n");
	printHex(ct2, 32, "after encryption:");
	// ����32�ֽ�����
	aesDecrypt(key2, 16, ct2, plain2, 32);
	// ��ӡ16������ʽ�Ľ��ܺ������
	printHex(plain2, 32, "after decryption:");

	// ��Ϊ����ǰ������Ϊ�ɼ��ַ����ַ�������ӡ���ܺ�������ַ��������ǰ���Ľ��жԱ�
	printf("output plain text\n");
	for (int i = 0; i < 32; ++i) {
		printf("%c ", plain2[i]);
	}

	return 0;
}
