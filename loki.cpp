#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "loki91_lib.cpp"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#if DEVELOP_MODE
#define Assert(Expression) if (!(Expression)) *((int *)0) = 0;
#else
#define Assert(Expression)
#endif

#define InvalidCodePath Assert(0)
#define InvalidDefaultCase default: {InvalidCodePath;} break;

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

struct string
{
    char *Data;
    u32 Len;
};

struct chipher_state
{
    int OpType;
    char *InputFileName;
    char *OutputFileName;

    u8 *ResultOutput;

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
    Exec_ParseError_InFileName = -8,
    Exec_ParseError_InFileSet,
    Exec_ParseError_InStrSet,
    Exec_ParseError_InNotSet,
    Exec_ParseError_OutFileName,
    Exec_ParseError_OpNotSet,
    Exec_ParseError_ArgCount,
    Exec_FileError_Open,

    ExecError_None = 0,
};

inline u32
GetAlignmentOffsetForwad(u32 Value, u32 Alignment)
{
	Assert(!(Alignment & (Alignment - 1)));

	u32 AlignOffset = 0;
	u32 AlignMask = Alignment - 1;
	u32 OffsetFromMask = (Value & AlignMask);

	if (OffsetFromMask)
	{
		AlignOffset = Alignment - OffsetFromMask;
	}

	return AlignOffset;
}

inline u32
AlignSize(u32 DataSize)
{
    u32 AlignOffset = GetAlignmentOffsetForwad(DataSize, 8);
    u32 Result = DataSize + AlignOffset;
    return Result;
}

void
DispatchError(s32 Error, char *Name = 0)
{
    switch (Error)
    {
        case Exec_ParseError_InFileName:
        {
           printf("Error: After -f must be filename\n");
        } break;

        case Exec_ParseError_InFileSet:
        {
            printf("Error: Input file already set, require to set only file or string\n");
        } break;

        case Exec_ParseError_InStrSet:
        {
            printf("Error: Input string already set, require to set only file or string\n");
        } break;

        case Exec_ParseError_InNotSet:
        {
            printf("Error: Input don't set");
        }

        case Exec_ParseError_OutFileName:
        {
            printf("Error: After -o must be filename\n");                
        } break;

        case Exec_ParseError_OpNotSet:
        {
            printf("Error: Type of operation must be choosen encrypt[-e] or decrypt[-d]\n");                
        } break;

        case Exec_ParseError_ArgCount:
        {
            printf("Error: Not enought argument\n");                
        } break;

        case Exec_FileError_Open:
        {
            char Buff[256];
            snprintf(Buff, sizeof(Buff), "Error: Cannot open %s file\n", Name);
            printf(Buff);
        }

        InvalidDefaultCase;
    }

    printf("loki -[e | d] [-f filename | string] [-o filename]\n");
}

file_content
ReadEntireFileIntoMemory(char *FileName)
{
    file_content Result = {};

    FILE *File = fopen(FileName, "r");
    if (File)
    {
        fseek(File, 0, SEEK_END);
        size_t FileSize = ftell(File);
        Result.Size = AlignSize(FileSize);

        Result.Data = (u8 *)calloc(Result.Size, sizeof(u8));
        fread(Result.Data, FileSize, 1, File);

        fclose(File);
    }

    return Result;
}

exec_error
InitDataFromFile(chipher_state *State)
{
    exec_error Error = ExecError_None;

    file_content InputFileContent = ReadEntireFileIntoMemory(State->InputFileName);
    
    if (InputFileContent.Data)
    {
        State->InputData.Data = InputFileContent.Data;
        State->InputData.Size = InputFileContent.Size;
    }
    else
    {
        Error = Exec_FileError_Open;
    }

    return Error;
}

exec_error
WriteOutputToFile(chipher_state *State)
{
    exec_error Error = ExecError_None;

    FILE *File = fopen(State->OutputFileName, "w");

    if (File)
    {
        fwrite(State->ResultOutput, sizeof(u8), State->InputData.Size, File);
        fclose(File);
    }
    else
    {
        Error = Exec_FileError_Open;
    }

    return Error;
}

exec_error
SetChipherArgs(chipher_state *State, char **Args)
{
    exec_error Error = ExecError_None;

    for (;*Args;)
    {
        if (strcmp(*Args, "-f") == 0)
        {
            if (!State->InputString.Data)
            {
                char *FileName = *++Args;
                if (FileName)
                {
                    State->InputFileName = FileName;
                }
                else
                {
                    Error = Exec_ParseError_InFileName;
                    break;
                }
            }
            else
            {
                Error = Exec_ParseError_InStrSet;
                break;
            }
        }
        else if (strcmp(*Args, "-o") == 0)
        {
            char *FileName = *++Args;
            if (FileName)
            {
                State->OutputFileName = FileName;
            }
            else
            {
               Error = Exec_ParseError_OutFileName;
               break;
            }
        }
        else
        {
            if (!State->InputFileName)
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
                    }
                    else
                    {
                        break;
                    }
                }
                Args = EndArgs;
                TotalLen++;
                TotalLen = AlignSize(TotalLen);

                State->InputString.Data = (char *)calloc(TotalLen * sizeof(char), sizeof(u8));
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
            else
            {
                Error = Exec_ParseError_InFileSet;
                break;
            }
        }
    }

    return Error;
}

exec_error
InitChiperState(chipher_state *State, int ArgCount, char **Args)
{
    exec_error Error = ExecError_None;

    if (ArgCount > 2)
    {
        if (strcmp(Args[1], "-e") == 0)
        {
            State->OpType = ChipherOpType_Encrypt;
        }
        else if (strcmp(Args[1], "-d") == 0)
        {
            State->OpType = ChipherOpType_Decrypt;
        }
        
        if (State->OpType != ChipherOpType_None)
        {
            Error = SetChipherArgs(State, Args + 2);

            if (Error == ExecError_None)
            {
                if (!State->InputFileName && !State->InputString.Data)
                {
                    Error = Exec_ParseError_InNotSet;
                }
            }
        }
        else
        {
            Error = Exec_ParseError_OpNotSet;
        }
    }
    else
    {
        Error = Exec_ParseError_ArgCount;
    }

    return Error;
}

// TODO: Set key input
int
main(int ArgCount, char **Args)
{
    chipher_state ChiperState = {};
    loki_key Key = {};

    exec_error Error = InitChiperState(&ChiperState, ArgCount, Args);
    if (Error == ExecError_None)
    {
        if (ChiperState.InputFileName)
        {
            Error = InitDataFromFile(&ChiperState);
            
            if(Error != ExecError_None)
            {
                DispatchError(Error, ChiperState.InputFileName);
            }
        }

        if (Error == ExecError_None)
        {
            ChiperState.ResultOutput = (u8 *)malloc(ChiperState.InputData.Size);

            switch (ChiperState.OpType)
            {
                case ChipherOpType_Encrypt:
                {
                    LokiEncrypt(Key, ChiperState.InputData.Data, ChiperState.InputData.Size, ChiperState.ResultOutput);
                } break;

                case ChipherOpType_Decrypt:
                {
                    LokiDecrypt(Key, ChiperState.InputData.Data, ChiperState.InputData.Size, ChiperState.ResultOutput);
                } break;
            }

            if (ChiperState.OutputFileName)
            {
                Error = WriteOutputToFile(&ChiperState);

                if(Error != ExecError_None)
                {
                    DispatchError(Error, ChiperState.OutputFileName);
                }
            }
            else
            {
                fwrite(ChiperState.ResultOutput, sizeof(u8), ChiperState.InputData.Size, stdout);
            }
        }
    }
    else
    {
        DispatchError(Error);
    }

    return (s32)Error;
}


// NOTE: Test code
s32
test(void)
{
    loki_key Key = {};
    Key.L = 0x12345678;
    Key.R = 0x09ABCDEF;
    
    // Encrypt
    char *EnText = "Hellow world from chipher";
    u32 EnLen = strlen(EnText);

    u32 EnAdjLen = AlignSize(EnLen);

    u8 *EnTest = (u8 *)calloc(EnAdjLen, sizeof(u8));
    memcpy(EnTest, EnText, EnLen);

    u8 *EnDestMem = (u8 *)calloc(EnAdjLen, sizeof(u8));

    LokiEncrypt(Key, EnTest, EnAdjLen, EnDestMem);
    
    for (u32 i = 0; i < EnAdjLen; ++i)
    {
        printf("%X", EnDestMem[i]);
    }
    printf("\n");
    
    const u8 DecByte[] = 
    {
        0xE2,0x99,0x27,0x14,0x19,0x36,0xBB,0xF7,0x4D,0xF6,0x55,0xFD,0x95,0xD0,0x1D,0x5E,
        0xDE,0x1D,0x66,0x6D,0xE2,0xBB,0xC1,0x88,0x9E,0xED,0x9C,0x51,0xC8,0xCB,0xBC,0x35
    };

    u32 DecLen = sizeof(DecByte);
    
    if (DecLen != EnAdjLen)
    {
        printf("Length don't match");
        return -1;
    }

    for (u32 i = 0; i < DecLen; ++i)
    {
        if (DecByte[i] != EnDestMem[i])
        {
            printf("Encypted data don't match");
            return -1;
        }
    }
    
    u32 DecAdjLen = AlignSize(DecLen);

    u8 *DecTest = (u8 *)calloc(DecAdjLen, sizeof(u8));
    memcpy(DecTest, DecByte, DecLen);

    u8 *DecDestMem = (u8 *)calloc(DecAdjLen, sizeof(u8));

    LokiDecrypt(Key, DecTest, DecAdjLen, DecDestMem);

    for (u32 i = 0; i < DecAdjLen; ++i)
    {
        printf("%c", DecDestMem[i]);
    }
    printf("\n");

	for (u32 i = 0; i < DecAdjLen; ++i)
	{
		if (EnTest[i] != DecDestMem[i])
		{
			printf("Plain data don't match");
			return -1;
		}
	}
}
