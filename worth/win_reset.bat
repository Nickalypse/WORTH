@echo [ELIMINAZIONE CLASSI COMPILATE]
@del /F/Q/S ".\server\class\*.*"
@del /F/Q/S ".\client\class\*.*"
@echo(

@echo [ELIMINAZIONE UTENTI]
@del /F/Q/S ".\server\home\users\*.*"
@echo(

@echo [ELIMINAZIONE PROGETTI]
@del /F/Q/S ".\server\home\projects\*.*"
@rmdir /Q/S ".\server\home\projects"
@mkdir ".\server\home\projects"

@echo(

@echo [RIPRISTINO IP MULTICAST INIZIALE]
@echo|set /p="239.0.0.0" > .\server\home\_ip\next_ip
@echo(

@echo [RIPRISTINO LISTA IP RECUPERATI]
@echo|set /p="" > .\server\home\_ip\free_ip
@echo(

@pause
