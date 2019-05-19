#ifndef AES_H_
#define ASE_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/////////////////////////////////////////�궨��//////////////////////////////////////////////////
#define BLOCKSIZE 16  //AES-128���鳤��Ϊ16�ֽ�;

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// ��uint32_t x����ȡ�ӵ�λ��ʼ�ĵ�n���ֽ�
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// �ֽ��滻Ȼ��ѭ������1λ
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

// uint32_t xѭ������nλ
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))

// uint32_t xѭ������nλ
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

/////////////////////////////////////////�ṹ��//////////////////////////////////////////////////
typedef struct {
	uint32_t eK[44], dK[44];    // encKey, decKey
	int Nr; // 10 rounds
}AesKey;


/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
// AES-128�ֳ���
static const uint32_t rcon[10] = {
		0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
		0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
};

/* copy in[16] to state[4][4] */
int loadStateArray(uint8_t(*state)[4],
	const uint8_t* in);

/* copy state[4][4] to out[16] */
int storeStateArray(uint8_t(*state)[4],
	uint8_t* out);

//��Կ��չ
int keyExpansion(const uint8_t* key,
	uint32_t keyLen,
	AesKey* aesKey);

// ����Կ��
int addRoundKey(uint8_t(*state)[4],
	const uint32_t* key);


//�ֽ��滻
int subBytes(uint8_t(*state)[4]);

//���ֽ��滻
int invSubBytes(uint8_t(*state)[4]);

//����λ
int shiftRows(uint8_t(*state)[4]);

//������λ
int invShiftRows(uint8_t(*state)[4]);

/* Galois Field (256) Multiplication of two Bytes */
// ���ֽڵ�٤�޻���˷�����
uint8_t GMul(uint8_t u,
	uint8_t v);

// �л��
int mixColumns(uint8_t(*state)[4]);

// ���л��
int invMixColumns(uint8_t(*state)[4]);

// AES-128���ܽӿڣ�����keyӦΪ16�ֽڳ��ȣ����볤��Ӧ����16�ֽ���������
// ����������������볤����ͬ�����������ⲿΪ������ݷ����ڴ�
int aesEncrypt(const uint8_t* key,
	uint32_t keyLen,
	const uint8_t* pt,
	uint8_t* ct,
	uint32_t len);

// AES128���ܣ� ����Ҫ��ͬ����
int aesDecrypt(const uint8_t* key,
	uint32_t keyLen,
	const uint8_t* ct,
	uint8_t* pt,
	uint32_t len);

#endif //AES_H_