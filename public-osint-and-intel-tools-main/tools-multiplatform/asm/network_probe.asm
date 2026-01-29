; Network Probe - Lackadaisical Security
; x64 Assembly for Windows
; https://lackadaisical-security.com/

bits 64
default rel

extern WSAStartup
extern WSACleanup
extern socket
extern connect
extern closesocket
extern inet_addr
extern htons
extern printf
extern ExitProcess

section .data
    banner db '================================================', 10
           db '  Network Probe - Lackadaisical Security', 10
           db '  https://lackadaisical-security.com/', 10
           db '================================================', 10, 10, 0
    
    testing_msg db 'Testing connectivity to %s:%d...', 10, 0
    success_msg db '[+] Connection successful!', 10, 0
    failed_msg db '[-] Connection failed!', 10, 0
    
    ; Test targets
    google_ip db '8.8.8.8', 0
    cloudflare_ip db '1.1.1.1', 0
    
    wsa_error db 'Failed to initialize Winsock', 10, 0

section .bss
    wsadata resb 408  ; WSADATA structure
    sockaddr resb 16  ; sockaddr_in structure

section .text
global main

main:
    ; Stack alignment
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    ; Print banner
    lea rcx, [banner]
    call printf
    
    ; Initialize Winsock
    mov rcx, 0x0202     ; Version 2.2
    lea rdx, [wsadata]
    call WSAStartup
    test rax, rax
    jnz .wsa_error
    
    ; Test Google DNS
    lea rcx, [google_ip]
    mov rdx, 53         ; DNS port
    call test_connection
    
    ; Test Cloudflare DNS
    lea rcx, [cloudflare_ip]
    mov rdx, 53
    call test_connection
    
    ; Cleanup
    call WSACleanup
    
    xor rcx, rcx
    call ExitProcess

.wsa_error:
    lea rcx, [wsa_error]
    call printf
    mov rcx, 1
    call ExitProcess

; Function: test_connection
; Parameters: RCX = IP address string, RDX = port
test_connection:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    ; Save parameters
    mov [rbp-8], rcx    ; IP address
    mov [rbp-16], rdx   ; Port
    
    ; Print testing message
    lea rcx, [testing_msg]
    mov rdx, [rbp-8]
    mov r8, [rbp-16]
    call printf
    
    ; Create socket
    mov rcx, 2          ; AF_INET
    mov rdx, 1          ; SOCK_STREAM
    xor r8d, r8d        ; IPPROTO_IP
    call socket
    mov [rbp-24], rax   ; Save socket handle
    
    cmp rax, -1
    je .connection_failed
    
    ; Setup sockaddr_in structure
    mov word [sockaddr], 2          ; sin_family = AF_INET
    mov ax, [rbp-16]
    xchg al, ah                     ; Convert to network byte order
    mov word [sockaddr+2], ax       ; sin_port
    
    ; Convert IP to network format
    mov rcx, [rbp-8]
    call inet_addr
    mov dword [sockaddr+4], eax     ; sin_addr
    
    ; Clear sin_zero
    xor eax, eax
    mov qword [sockaddr+8], rax
    
    ; Connect
    mov rcx, [rbp-24]               ; Socket
    lea rdx, [sockaddr]             ; Address
    mov r8d, 16                     ; Address length
    call connect
    
    test eax, eax
    jnz .connection_failed
    
    ; Success
    lea rcx, [success_msg]
    call printf
    jmp .cleanup

.connection_failed:
    lea rcx, [failed_msg]
    call printf

.cleanup:
    ; Close socket if valid
    mov rcx, [rbp-24]
    cmp rcx, -1
    je .done
    call closesocket

.done:
    mov rsp, rbp
    pop rbp
    ret