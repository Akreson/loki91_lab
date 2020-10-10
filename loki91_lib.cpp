#include <stdint.h>

struct loki_key
{
    union
    {
        u8 Byte[8]
        struct
        {
            u32 L;
            u32 H
        };
    }
}

void
loki_encrypt(loki_key Key, u8 *InputData, u32 DataLen, u8 *OutputBuffer)
{

}

void
loki_decrypt(loki_key Key, u8 *InputData, u32 DataLen, u8 *OutputBuffer)
{

}