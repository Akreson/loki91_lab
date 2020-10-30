#include "loki.h"
#include "loki91_lib.cpp"

inline u32
GetAlignmentOffsetForwad(u32 Value, u32 Alignment = 8)
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
    u32 AlignOffset = GetAlignmentOffsetForwad(DataSize);
    u32 Result = DataSize + AlignOffset;
    return Result;
}

b32
ScanHexString(u8 *Out, char *In, u32 Size)
{
    b32 Succes = true;

    u32 Shift[] = {0, 4};
    u32 ShiftToggle = 1;
	u32 MoveOutPtr = 0;

    for (u32 Index = 0;
        Index < Size;
        ++Index)
    {
        u8 OutValue = *Out;
        char InValue = In[Index];
        u8 Digit = CharToDigit[InValue];

        if ((Digit == 0) && (InValue != '0'))
        {
            Succes = false;
            break;
        }

        OutValue |= Digit << Shift[ShiftToggle];
        *Out = OutValue;
        Out += MoveOutPtr;
        ShiftToggle = !ShiftToggle;
		MoveOutPtr = !MoveOutPtr;
    }

    return Succes;
}

void
DispatchError(s32 Error, char *InName = 0, char *OutName = 0)
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
            printf("Error: Input don't set\n");
        } break;

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

        case Exec_ParseError_KeyFlag:
        {
            printf("Error: Invalid key flag, allowed variation -k[h | f]\n");
        } break;

        case Exec_ParamError_NotHexStr:
        {
            printf("Error: -kh argument contain not hex charaster\n");
        } break;

        case Exec_ParseError_Key:
        {
            printf("Error: Key not set\n");
        } break;

        case Exec_FileError_InOpen:
        {
            char Buff[256];
            snprintf(Buff, sizeof(Buff), "Error: Cannot open input file - %s\n", InName);
            printf(Buff);
        } break;

        case Exec_FileError_OutOpen:
        {
            char Buff[256];
            snprintf(Buff, sizeof(Buff), "Error: Cannot open output file - %s\n", OutName);
            printf(Buff);
        } break;

        case Exec_FileError_KeyOpen:
        {
            printf("Error: Cannot open key sotore file\n");
        } break;

        case Exec_FileError_DecAlign:
        {
            printf("Error: File not loki encrypted or has been modified\n");
        } break;

        InvalidDefaultCase;
    }

    printf("loki -[e | d] -k[h | f] [-f filename | string] [-o filename]\n");
}

size_t
GetFileSize(FILE *File)
{
    size_t Result = 0;

    fseek(File, 0, SEEK_END);
    Result = ftell(File);
	fseek(File, 0, SEEK_SET);

    return Result;
}

exec_error
InitDataFromFile(chipher_state *State)
{
    exec_error Error = ExecError_None;
    FILE *InputFile = fopen(State->InputFileName, "rb");

    if(InputFile)
    {
        u32 FileSize = (u32)GetFileSize(InputFile);
        u32 AlignOffset = GetAlignmentOffsetForwad(FileSize);

        switch (State->OpType)
        {
            case ChipherOpType_Encrypt:
            {
                u32 AllocSize;

                if (AlignOffset == 0)
                {
                    AllocSize = FileSize + LOKI_BLOCK_SIZE; 
                }
                else
                {
                    AllocSize = FileSize + AlignOffset;
                }

                State->InputData.Size = AllocSize;
                State->InputData.Data = (u8 *)malloc(AllocSize);

                u32 BytesToFill = AllocSize - FileSize;
                u8 *Data = State->InputData.Data + FileSize;
                memset(Data, AlignOffset, BytesToFill);

                fread(State->InputData.Data, FileSize, 1, InputFile);
                fclose(InputFile);
            } break;

            case ChipherOpType_Decrypt:
            {
                if (AlignOffset == 0)
                {
                    State->InputData.Size = FileSize;
                    State->InputData.Data = (u8 *)malloc(FileSize);
                    
                    fread(State->InputData.Data, FileSize, 1, InputFile);
                    fclose(InputFile);
                }
                else
                {
                    Error = Exec_FileError_DecAlign;
                }
            } break;
        }
    }
    else
    {
        Error = Exec_FileError_InOpen;
    }


    return Error;
}

exec_error
WriteOutputToFile(chipher_state *State)
{
    exec_error Error = ExecError_None;

    FILE *File = fopen(State->OutputFileName, "wb");

    if (File)
    {
        switch (State->OpType)
        {
            case ChipherOpType_Encrypt:
            {
                fwrite(State->ResultOutput, sizeof(u8), State->InputData.Size, File);
            } break;

            case ChipherOpType_Decrypt:
            {
                u32 PaddingSize = (u32)State->ResultOutput[State->InputData.Size - 1];
                PaddingSize = (PaddingSize != 0) ? PaddingSize : LOKI_BLOCK_SIZE;
                Assert(PaddingSize != 8);

                u32 WriteSize = State->InputData.Size - PaddingSize;
                fwrite(State->ResultOutput, sizeof(u8), WriteSize, File);
            } break;
        }

        fclose(File);
    }
    else
    {
        Error = Exec_FileError_OutOpen;
    }

    return Error;
}

exec_error
ReadKeyFromFile(u8 *Buff, char *FileName)
{
    exec_error Error = ExecError_None;

    FILE *File = fopen(FileName, "rb");

    if (File)
    {
        fseek(File, 0, SEEK_END);
        size_t FileSize = ftell(File);
        fseek(File, 0, SEEK_SET);

        if (FileSize >= LOKI_KEY_SIZE)
        {
            fread(Buff, LOKI_KEY_SIZE, 1, File);
        }
        else
        {
            fread(Buff, FileSize, 1, File);
        }
    }
    else
    {
        Error = Exec_FileError_KeyOpen;
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

            *++Args;
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

            *++Args;
        }
        else if (((*Args)[0] == '-') && ((*Args)[1] == 'k'))
        {
            u32 KeyFlagLen = (u32)strlen(*Args);
            if (KeyFlagLen == 3)
            {
                if ((*Args)[2] == 'h')
                {
                    State->InputKey.Type = KeyType_Hex;
                }
                else if ((*Args)[2] == 'f')
                {
                    State->InputKey.Type = KeyType_File;
                }
                else
                {
                    Error = Exec_ParseError_KeyFlag;
                    break;
                }
            }
            else if (KeyFlagLen > 3)
            {
                Error = Exec_ParseError_KeyFlag;
                break;
            }
            else
            {
                State->InputKey.Type = KeyType_Str;
            }

            char *KeyValueStr = *++Args;
            State->InputKey.Data = KeyValueStr;
            State->InputKey.Len = (u32)strlen(KeyValueStr);
            *++Args;
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
                        TotalLen += (u32)(strlen(CurrArg) + 1);
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
                    u32 StrLen = (u32)strlen(*CopyArg);
                    memcpy((void *)Dest, (void *)*CopyArg, StrLen);
                    Dest += StrLen;
                    *Dest++ = ' ';
                }
                *Dest = 0;
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

            if (Error == ExecError_None && 
                (!State->InputFileName && !State->InputString.Data))
            {
                Error = Exec_ParseError_InNotSet;
            }

            if (Error == ExecError_None && !State->InputKey.Data)
            {
                Error = Exec_ParseError_Key;
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

exec_error
InitLokiKey(loki_key *Key, input_key InputKey)
{
    exec_error Error = ExecError_None;
    
    switch (InputKey.Type)
    {
        case KeyType_Str:
        {
            u32 StrKeyLen = InputKey.Len >= LOKI_KEY_SIZE ? LOKI_KEY_SIZE : InputKey.Len;
            memcpy(Key->Buff, InputKey.Data, StrKeyLen);
        } break;

        case KeyType_Hex:
        {
            u32 HexByteLen = InputKey.Len / 2;
            u32 KeyLen = HexByteLen >= LOKI_KEY_SIZE ? LOKI_KEY_SIZE*2 : InputKey.Len;

            if (!ScanHexString(Key->Buff, InputKey.Data, KeyLen))
            {
                Error = Exec_ParamError_NotHexStr;
            }
        } break;
        
        case KeyType_File:
        {
            Error = ReadKeyFromFile(Key->Buff, InputKey.Data);
        } break;

        InvalidDefaultCase;
    }
    
    return Error;
}

void
StartChipherOperation(chipher_state *State, loki_key Key)
{
    switch (State->OpType)
    {
        case ChipherOpType_Encrypt:
        {
            LokiEncrypt(Key, State->InputData.Data, State->InputData.Size, State->ResultOutput);
        } break;

        case ChipherOpType_Decrypt:
        {
            LokiDecrypt(Key, State->InputData.Data, State->InputData.Size, State->ResultOutput);
        } break;
    }
}

int
main(int ArgCount, char **Args)
{
    InitCharToDigitArr();
    
    chipher_state ChiperState = {};

    exec_error Error = InitChiperState(&ChiperState, ArgCount, Args);
    if (Error == ExecError_None)
    {
        loki_key Key = {};
        Error = InitLokiKey(&Key, ChiperState.InputKey);

        if ((Error == ExecError_None) && ChiperState.InputFileName)
        {
            Error = InitDataFromFile(&ChiperState);
        }

        if (Error == ExecError_None)
        {
            ChiperState.ResultOutput = (u8 *)malloc(ChiperState.InputData.Size);

            StartChipherOperation(&ChiperState, Key);

            if (ChiperState.OutputFileName)
            {
                Error = WriteOutputToFile(&ChiperState);
            }
            else
            {
                fwrite(ChiperState.ResultOutput, sizeof(u8), ChiperState.InputData.Size, stdout);
            }
        }
    }

    if(Error != ExecError_None)
    {
        DispatchError(Error, ChiperState.InputFileName, ChiperState.OutputFileName);
    }
    
    return (s32)Error;
}

// NOTE: Some test code ----------------------
#if 0
int
test(void)
{
    ChiperState.InputFileName = "";
    InitDataFromFile(&ChiperState);
    ChiperState.ResultOutput = (u8 *)calloc(ChiperState.InputData.Size, sizeof(u8));

    loki_key Key = {};
    Key.L = 0xABCDEF90;
    Key.R = 0x12345678;

    LokiEncrypt(Key, ChiperState.InputData.Data, ChiperState.InputData.Size, ChiperState.ResultOutput);

    FILE *EFile = fopen("ENC.loki", "wb");
    fwrite(ChiperState.ResultOutput, sizeof(u8), ChiperState.InputData.Size, EFile);
    fclose(EFile);

    file_content SavedFile = ReadEntireFileIntoMemory("ENC.loki");
     for (u32 i = 0; i < ChiperState.InputData.Size; i++)
    {
        if (SavedFile.Data[i] != ChiperState.ResultOutput[i]) Assert(0);
    }

    u8 *OutBuffer = (u8 *)calloc(ChiperState.InputData.Size, sizeof(u8));
    LokiDecrypt(Key, SavedFile.Data, ChiperState.InputData.Size, OutBuffer);
	
    for (u32 i = 0; i < ChiperState.InputData.Size; i++)
    {
        if (OutBuffer[i] != ChiperState.InputData.Data[i]) Assert(0);
    }

    FILE *DFile = fopen("DEC.loki", "wb");
    fwrite(OutBuffer, sizeof(u8), ChiperState.InputData.Size, DFile);
    fclose(DFile);

    return 0
}
#endif