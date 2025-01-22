/*
 *  Copyright 2011-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "empty-pkcs11.h"


CK_FUNCTION_LIST empty_pkcs11_2_40_functions = 
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_INTERFACE empty_pkcs11_2_40_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_2_40_functions,
	0
};


CK_FUNCTION_LIST_3_0  empty_pkcs11_3_1_functions =
{
	{0x03, 0x01},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal
};


CK_INTERFACE empty_pkcs11_3_1_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_3_1_functions,
	0
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	UNUSED(pInitArgs);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	UNUSED(pReserved);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &empty_pkcs11_2_40_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	UNUSED(tokenPresent);
	UNUSED(pSlotList);
	UNUSED(pulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	UNUSED(slotID);
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	UNUSED(slotID);
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	UNUSED(slotID);
	UNUSED(pMechanismList);
	UNUSED(pulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	UNUSED(slotID);
	UNUSED(type);
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	UNUSED(slotID);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pLabel);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	UNUSED(hSession);
	UNUSED(pOldPin);
	UNUSED(ulOldLen);
	UNUSED(pNewPin);
	UNUSED(ulNewLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	UNUSED(slotID);
	UNUSED(flags);
	UNUSED(pApplication);
	UNUSED(Notify);
	UNUSED(phSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	UNUSED(slotID);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	UNUSED(hSession);
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(pulOperationStateLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(ulOperationStateLen);
	UNUSED(hEncryptionKey);
	UNUSED(hAuthenticationKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phNewObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	UNUSED(hSession);
	UNUSED(hObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pulSize);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	UNUSED(hSession);
	UNUSED(phObject);
	UNUSED(ulMaxObjectCount);
	UNUSED(pulObjectCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pEncryptedData);
	UNUSED(pulEncryptedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastEncryptedPart);
	UNUSED(pulLastEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedData);
	UNUSED(ulEncryptedDataLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastPart);
	UNUSED(pulLastPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	UNUSED(hSession);
	UNUSED(pMechanism);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pPublicKeyTemplate);
	UNUSED(ulPublicKeyAttributeCount);
	UNUSED(pPrivateKeyTemplate);
	UNUSED(ulPrivateKeyAttributeCount);
	UNUSED(phPublicKey);
	UNUSED(phPrivateKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hBaseKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	UNUSED(hSession);
	UNUSED(pSeed);
	UNUSED(ulSeedLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	UNUSED(hSession);
	UNUSED(RandomData);
	UNUSED(ulRandomLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	UNUSED(flags);
	UNUSED(pSlot);
	UNUSED(pReserved);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pInterfacesList)
	{
		*pulCount = 2;
	}
	else
	{
		if (*pulCount < 2)
			return CKR_BUFFER_TOO_SMALL;

		pInterfacesList[0].pInterfaceName = empty_pkcs11_2_40_interface.pInterfaceName;
		pInterfacesList[0].pFunctionList = empty_pkcs11_2_40_interface.pFunctionList;
		pInterfacesList[0].flags = empty_pkcs11_2_40_interface.flags;

		pInterfacesList[1].pInterfaceName = empty_pkcs11_3_1_interface.pInterfaceName;
		pInterfacesList[1].pFunctionList = empty_pkcs11_3_1_interface.pFunctionList;
		pInterfacesList[1].flags = empty_pkcs11_3_1_interface.flags;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	if (NULL == ppInterface)
		return CKR_ARGUMENTS_BAD;

	if (flags != 0)
	{
		*ppInterface = NULL;
		return CKR_OK;
	}

	if (NULL != pInterfaceName)
	{
		const char* requested_interface_name = (const char*)pInterfaceName;
		const char* supported_interface_name = "PKCS 11";

		if (strlen(requested_interface_name) != strlen(supported_interface_name) || 0 != strcmp(requested_interface_name, supported_interface_name))
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	if (NULL != pVersion)
	{
		if (pVersion->major == empty_pkcs11_2_40_functions.version.major && pVersion->minor == empty_pkcs11_2_40_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_2_40_interface;
			return CKR_OK;
		}
		else if (pVersion->major == empty_pkcs11_3_1_functions.version.major && pVersion->minor == empty_pkcs11_3_1_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_3_1_interface;
			return CKR_OK;
		}
		else
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	*ppInterface = &empty_pkcs11_3_1_interface;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}
