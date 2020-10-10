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
    char *InputFile;
    char *OutputFile;

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
                    State->InputFile = FileName;
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
                State->OutputFile = FileName;
            }
            else
            {
               Error = Exec_ParseError_OutFileName;
               break;
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
                if (!State->InputFile && !State->InputString.Data)
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

    exec_error Error = InitChiperState(&ChiperState, ArgCount, Args);
    if (Error == ExecError_None)
    {
        if (ChiperState.InputFile)
        {
            file_content InputFileContent = ReadEntireFileIntoMemory(ChiperState.InputFile);
            if (InputFileContent.Data)
            {
                ChiperState.InputData.Data = InputFileContent.Data;
                ChiperState.InputData.Size = InputFileContent.Size;
            }
            else
            {
                DispatchError(Exec_FileError_Open, ChiperState.InputFile);
            }
        }

        // TODO: Call encr decr function here
        switch (ChiperState.OpType)
        {
            case ChipherOpType_Encrypt:
            {

            } break;

            case ChipherOpType_Decrypt:
            {

            } break;
        }
    }
    else
    {
        DispatchError(Error);
    }

    return (s32)Error;
}