#ifndef AES_H_
#define ASE_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/////////////////////////////////////////宏定义//////////////////////////////////////////////////
#define BLOCKSIZE 16  //AES-128分组长度为16字节;

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// 从uint32_t x中提取从低位开始的第n个字节
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// 字节替换然后循环左移1位
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

// uint32_t x循环左移n位
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))

// uint32_t x循环右移n位
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

/////////////////////////////////////////结构体//////////////////////////////////////////////////
typedef struct {
	uint32_t eK[44], dK[44];    // encKey, decKey
	int Nr; // 10 rounds
}AesKey;


/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
// AES-128轮常量
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

//秘钥扩展
int keyExpansion(const uint8_t* key,
	uint32_t keyLen,
	AesKey* aesKey);

// 轮秘钥加
int addRoundKey(uint8_t(*state)[4],
	const uint32_t* key);


//字节替换
int subBytes(uint8_t(*state)[4]);

//逆字节替换
int invSubBytes(uint8_t(*state)[4]);

//行移位
int shiftRows(uint8_t(*state)[4]);

//逆行移位
int invShiftRows(uint8_t(*state)[4]);

/* Galois Field (256) Multiplication of two Bytes */
// 两字节的伽罗华域乘法运算
uint8_t GMul(uint8_t u,
	uint8_t v);

// 列混合
int mixColumns(uint8_t(*state)[4]);

// 逆列混合
int invMixColumns(uint8_t(*state)[4]);

// AES-128加密接口，输入key应为16字节长度，输入长度应该是16字节整倍数，
// 这样输出长度与输入长度相同，函数调用外部为输出数据分配内存
int aesEncrypt(const uint8_t* key,
	uint32_t keyLen,
	const uint8_t* pt,
	uint8_t* ct,
	uint32_t len);

// AES128解密， 参数要求同加密
int aesDecrypt(const uint8_t* key,
	uint32_t keyLen,
	const uint8_t* ct,
	uint8_t* pt,
	uint32_t len);

#endif //AES_H_