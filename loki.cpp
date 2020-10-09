#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "loki91_lib.cpp"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef size_t memory_index;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

enum chipher_op_type
{
    ChipherOpType_None,

    ChipherOpType_Encrypt,
    ChipherOpType_Decrypt,
};

struct string
{
    char *Data;
    u32 Len;
};

struct chipher_state
{
    int OpType;
    string InputString;
    char *InputFile;
    char *OutputFile;
};

void
SetLokiArgs(chipher_state *State, char **Args)
{
    for (;*Args;)
    {
        if (strcmp(*Args, "-f") == 0)
        {
            if (!State->InputString.Data)
            {
                char *FileName = *++Args;
                if (FileName)
                {
                    State->InputFile = FileName;
                }
                else
                {
                    // TODO: Handle Error
                }
            }
            else
            {
                printf("Input already set");
				break;
                // TODO: Handle Error
            }
        }
        else if (strcmp(*Args, "-o") == 0)
        {
            char *FileName = *++Args;
            if (FileName)
            {
                State->OutputFile = FileName;
            }
            else
            {
                // TODO: Handle Error
            }
        }
        else
        {
            if (!State->InputFile)
            {
                u32 TotalLen = 0;
                char **StartArg = Args;
                char **EndArgs = StartArg;
                
                for (;*EndArgs; ++EndArgs)
                {
                    char *CurrArg = *EndArgs;

                    if ((strcmp(CurrArg, "-f") != 0) && (strcmp(CurrArg, "-o") != 0))
                    {
                        TotalLen += (strlen(CurrArg) + 1);
                        printf("%s\n", CurrArg);
                    }
                    else
                    {
                        break;
                    }
                }
                Args = EndArgs;
                TotalLen++;

                State->InputString.Data = (char *)malloc(TotalLen * sizeof(char));
                State->InputString.Len = TotalLen;

                char *Dest = State->InputString.Data;
                char **CopyArg = StartArg;
                for (; CopyArg != EndArgs; ++CopyArg)
                {
                    u32 StrLen = strlen(*CopyArg);
                    memcpy((void *)Dest, (void *)*CopyArg, StrLen);
                    Dest += StrLen;
                    *Dest++ = ' ';
                }
                *Dest = 0;
                printf("Sting: %s\n", State->InputString.Data);
            }
        }
    }   
}

chipher_state
InitChiperState(int ArgCount, char **Args)
{
    chipher_state Result = {};

    if (ArgCount > 2)
    {
        if (strcmp(Args[1], "-e") == 0)
        {
            Result.OpType = ChipherOpType_Encrypt;
        }
        else if (strcmp(Args[1], "-d") == 0)
        {
            Result.OpType = ChipherOpType_Decrypt;
        }
        
        if (Result.OpType != ChipherOpType_None)
        {
            SetLokiArgs(&Result, Args + 2);
        }
        else
        {
            // TODO: Handle error
        }
    }
    else
    {
        // TODO: Handle error
    }

    return Result;
}

// loki -e[d] [-f filename | string] [-o filename]
int
main(int ArgCount, char **Args)
{
    chipher_state LokiState = InitChiperState(ArgCount, Args);
}