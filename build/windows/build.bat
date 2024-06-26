@rem Build for x86 platform
@setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
msbuild empty-pkcs11.sln /p:Configuration=Release /p:Platform=Win32 /target:Clean || goto :error
msbuild empty-pkcs11.sln /p:Configuration=Release /p:Platform=Win32 /target:Build || goto :error
copy .\Win32\Release\empty-pkcs11-x86.dll . || goto :error
@endlocal

@rem Build for x64 platform
@setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
msbuild empty-pkcs11.sln /p:Configuration=Release /p:Platform=x64 /target:Clean || goto :error
msbuild empty-pkcs11.sln /p:Configuration=Release /p:Platform=x64 /target:Build || goto :error
copy .\x64\Release\empty-pkcs11-x64.dll . || goto :error
@endlocal

@echo *** BUILD SUCCESSFUL ***
@exit /b %errorlevel%

:error
@echo *** BUILD FAILED ***
@endlocal
@exit /b %errorlevel%
