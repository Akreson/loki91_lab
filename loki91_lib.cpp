#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#define internal static

#define LOKI_KEY_SIZE 8

#define ROUNDS	16
#define BLOCK_SIZE 8
#define MASK12	0x0fff

const u8 PerpVal[32] =
{
	31, 23, 15, 7, 30, 22, 14, 6,
	29, 21, 13, 5, 28, 20, 12, 4,
	27, 19, 11, 3, 26, 18, 10, 2,
	25, 17, 9, 1, 24, 16, 8, 0
};

struct s_box_fn_desc
{
    u16	Gen;
    u16	Exp;
};

s_box_fn_desc SBoxFun[] =
{
	{ /* 101110111 */ 375, 31},
	{ /* 101111011 */ 379, 31},
	{ /* 110000111 */ 391, 31},
	{ /* 110001011 */ 395, 31},
	{ /* 110001101 */ 397, 31},
	{ /* 110011111 */ 415, 31},
	{ /* 110100011 */ 419, 31},
	{ /* 110101001 */ 425, 31},
	{ /* 110110001 */ 433, 31},
	{ /* 110111101 */ 445, 31},
	{ /* 111000011 */ 451, 31},
	{ /* 111001111 */ 463, 31},
	{ /* 111010111 */ 471, 31},
	{ /* 111011101 */ 477, 31},
	{ /* 111100111 */ 487, 31},
	{ /* 111110011 */ 499, 31},
	{ 00, 00}
};

struct loki_key
{
    union
    {
        u64 Value;
        u8 Buff[8];

        struct
        {
            u32 L;
            u32 R;
        };
    };
};

struct work_block
{
    u32 L;
    u32 R;
};

struct loki_subkeys
{
    u32 Key[16];
};

inline u32
Rol12(u32 A)
{
    u32 Result = ((A << 12) | (A >> 20));
    return Result;
}

inline u32
Rol13(u32 A)
{
    u32 Result = ((A << 13) | (A >> 19));
    return Result;
}

loki_subkeys
SetSubKey(loki_key Key)
{
    loki_subkeys Result = {};

    u32 KL = Key.L;
    u32 KR = Key.R;

    for (u32 Index = 0;
        Index < ROUNDS;
        Index += 4)
    {
        Result.Key[Index] = KL;
        KL = Rol12(KL);
        Result.Key[Index + 1] = KL;
        KL = Rol13(KL);
        Result.Key[Index + 2] = KR;
        KR = Rol12(KR);
        Result.Key[Index + 3] = KR;
        KR = Rol13(KR);
    }

    return Result;
}

#define SIZE 256
internal u16
Mul8(u16 A, u16 B, u16 Gen)
{
    u16 Product = 0;

    while (B != 0)
    {
        if (B & 0x1)
            Product ^= A;
        
        A <<= 1;
        if (A >= SIZE)
            A ^= Gen;

        B >>= 1;
    }

    return Product;
}
#undef SIZE

internal u16
Exp8(u16 Base, u16 Exponent, u16 Gen)
{
    u16 Accum = Base;
    u16 Result = 0;

    if (Base != 0)
    {
        Result = 1;
    
        while (Exponent != 0)
        {
            if ((Exponent & 0x0001) == 0x0001)
                Result = Mul8(Result, Accum, Gen);
            Exponent >>= 1;
            Accum = Mul8(Accum, Accum, Gen);
        }
    }

    return Result;
}

#define	MSB	0x80000000L /* MSB of 32-bit word */

internal void
Perm32(u32 *Out, u32 *In)
{
    u32 Mask = MSB;
    const u8 *P = PerpVal;
    *Out = 0;

    u32 I, B;
    for (u32 OutBitIndex = 0; OutBitIndex < 32; ++OutBitIndex) /* For each output bit position*/
    {
        I = (u32)*P++;
        B = (*In >> I) & 0x1;
        if (B)
            *Out |= Mask;
        Mask >>= 1;
    }
}

internal u32
LokiSBox(u32 Value)
{
    u16 R = ((Value >> 8) & 0xC) | (Value & 0x3);  /* row value-top 2 & bottom 2 */
    u16 C = (Value >> 2) & 0xFF;                   /* column value-middle 8 bits */
    u16 T = (C + ((R * 17) ^ 0xFF)) & 0xFF;        /* base value for Sfn */

    s_box_fn_desc SBoxValue = SBoxFun[R];
    u16 Result = Exp8(T, SBoxValue.Exp, SBoxValue.Gen); /* Sfn[r] = t ^ exp mod gen */
    return Result;
}

internal u32
LokiFunc(u32 Value, u32 Key)
{
    u32 Result;

    u32 A = Value ^ Key;

    u32 B = ((u32)LokiSBox(A & MASK12)) |
            ((u32)LokiSBox(((A >> 8) & MASK12)) << 8) |
            ((u32)LokiSBox(((A >> 16) & MASK12)) << 16) |
            ((u32)LokiSBox(((A >> 24) | (A << 8)) & MASK12) << 24);

    Perm32(&Result, &B);

    return Result;
}

void
LokiEncrypt(loki_key Key, u8 *InputData, u32 DataLen, u8 *OutputBuffer)
{
    loki_subkeys SubKey = SetSubKey(Key);
    u32 BlockCount = DataLen / BLOCK_SIZE;
    
    work_block *InBlocks = (work_block *)InputData;
    work_block *OutBlocks = (work_block *)OutputBuffer;

    for (u32 BlockIndex = 0;
        BlockIndex < BlockCount;
        ++BlockIndex)
    {
        work_block Block = InBlocks[BlockIndex];

        for (u32 Index = 0;
            Index < ROUNDS;
            Index += 2)
        {
            Block.L ^= LokiFunc(Block.R, SubKey.Key[Index]);
            Block.R ^= LokiFunc(Block.L, SubKey.Key[Index + 1]);
        }

        work_block *Out = OutBlocks + BlockIndex;
        Out->L = Block.R;
        Out->R = Block.L;
    }
}

void
LokiDecrypt(loki_key Key, u8 *InputData, u32 DataLen, u8 *OutputBuffer)
{
    loki_subkeys SubKey = SetSubKey(Key);
    u32 BlockCount = DataLen / BLOCK_SIZE;
    
    work_block *InBlocks = (work_block *)InputData;
    work_block *OutBlocks = (work_block *)OutputBuffer;

    for (u32 BlockIndex = 0;
        BlockIndex < BlockCount;
        ++BlockIndex)
    {
        work_block Block = InBlocks[BlockIndex];

        for (u32 Index = ROUNDS;
            Index > 0;
            Index -= 2)
        {
            Block.L ^= LokiFunc(Block.R, SubKey.Key[Index - 1]);
            Block.R ^= LokiFunc(Block.L, SubKey.Key[Index - 2]);
        }

        work_block *Out = OutBlocks + BlockIndex;
        Out->L = Block.R;
        Out->R = Block.L;
    }
}