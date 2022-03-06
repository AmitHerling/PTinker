#pragma once

typedef enum {named, list, sign} ActionType;
typedef union { DWORD pId; TCHAR* pName } Proc;