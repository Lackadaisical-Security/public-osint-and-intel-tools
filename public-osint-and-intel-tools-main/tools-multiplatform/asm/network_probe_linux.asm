; Network Probe Linux - Lackadaisical Security
; x64 Assembly for Linux
; https://lackadaisical-security.com/

global _start
extern printf
extern socket
extern connect
extern close
extern inet_addr
extern htons
extern exit

section .data
    banner db '================================================', 10
           db '  Network Probe - Lackadaisical Security', 10
           db '  https://lackadaisical-security.com/', 10
           db '================================================', 10, 10, 0
    
    testing_msg db 'Testing connectivity to %s:%d...', 10, 0
    success_msg db '[+] Connection successful!', 10, 0
    failed_msg db '[-] Connection failed!', 10, 0
    
    ; Test targets
    google_dns db '8.8.8.8', 0
    cloudflare_dns db '1.1.1.1', 0
    
    port dw 53  ; DNS port

section .bss
    sockfd resd 1
    sockaddr resb 16

section .text
_start:
    ; Print banner
    mov rdi, banner
    xor rax, rax
    call printf
    
    ; Test Google DNS
    mov rdi, google_dns
    movzx rsi, word [port]
    call test_connection
    
    ; Test Cloudflare DNS
    mov rdi, cloudflare_dns
    movzx rsi, word [port]
    call test_connection
    
    ; Exit
    xor rdi, rdi
    call exit

test_connection:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rdi    ; Save IP string
    mov r13, rsi    ; Save port
    
    ; Print testing message
    mov rdi, testing_msg
    mov rsi, r12
    mov rdx, r13
    xor rax, rax
    call printf
    
    ; Create socket
    mov rdi, 2      ; AF_INET
    mov rsi, 1      ; SOCK_STREAM
    xor rdx, rdx    ; Protocol
    call socket
    
    mov [sockfd], eax
    cmp rax, -1
    je .failed
    
    ; Setup sockaddr_in
    mov word [sockaddr], 2          ; sin_family = AF_INET
    mov di, r13w
    call htons
    mov word [sockaddr+2], ax       ; sin_port
    
    mov rdi, r12
    call inet_addr
    mov dword [sockaddr+4], eax     ; sin_addr
    
    ; Clear sin_zero
    xor rax, rax
    mov qword [sockaddr+8], rax
    
    ; Connect
    mov edi, [sockfd]
    mov rsi, sockaddr
    mov rdx, 16
    call connect
    
    test rax, rax
    jnz .failed
    
    ; Success
    mov rdi, success_msg
    xor rax, rax
    call printf
    jmp .cleanup

.failed:
    mov rdi, failed_msg
    xor rax, rax
    call printf

.cleanup:
    mov edi, [sockfd]
    call close
    
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret