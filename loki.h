#if !defined(LOKI_H)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

struct file_content
{
    u8 *Data;
    u32 Size;
};

enum chipher_op_type
{
    ChipherOpType_None,

    ChipherOpType_Encrypt,
    ChipherOpType_Decrypt,
};

enum input_key_type
{
    KeyType_Str,
    KeyType_Hex,
    KeyType_File,
};

struct string
{
    char *Data;
    u32 Len;
};

struct input_key
{
    char *Data;
    u32 Len;
    input_key_type Type;
};

struct chipher_state
{
    int OpType;
    char *InputFileName;
    char *OutputFileName;

    u8 *ResultOutput;

    input_key InputKey;

    union
    {
        string InputString;

        struct
        {
            u8 *Data;
            u32 Size;
        } InputData;
    };
};

enum exec_error
{
    Exec_ParseError_InFileName = -14,
    Exec_ParseError_InFileSet,
    Exec_ParseError_InStrSet,
    Exec_ParseError_InNotSet,
    Exec_ParseError_OutFileName,
    Exec_ParseError_OpNotSet,
    Exec_ParseError_ArgCount,
    Exec_ParseError_KeyFlag,
    Exec_ParamError_NotHexStr,
    Exec_ParseError_Key,
    Exec_FileError_InOpen,
    Exec_FileError_OutOpen,
    Exec_FileError_KeyOpen,
    Exec_FileError_DecAlign,

    ExecError_None = 0,
};

static u8 CharToDigit[256] = {};

// "Designated Initializers" don't work((
void
InitCharToDigitArr(void)
{
    CharToDigit['0'] = 0,
    CharToDigit['1'] = 1,
    CharToDigit['2'] = 2,
    CharToDigit['3'] = 3,
    CharToDigit['4'] = 4,
    CharToDigit['5'] = 5,
    CharToDigit['6'] = 6,
    CharToDigit['7'] = 7,
    CharToDigit['8'] = 8,
    CharToDigit['9'] = 9,
    CharToDigit['a'] = CharToDigit['A'] = 10;
    CharToDigit['b'] = CharToDigit['B'] = 11;
    CharToDigit['c'] = CharToDigit['C'] = 12;
    CharToDigit['d'] = CharToDigit['D'] = 13;
    CharToDigit['e'] = CharToDigit['E'] = 14;
    CharToDigit['f'] = CharToDigit['F'] = 15;
}

#define LOKI_H
#endif