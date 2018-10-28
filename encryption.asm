extern puts
extern printf

section .data
filename: db "./input.dat",0
inputlen: dd 2263
fmtstr: db "Key: %d",0xa,0

section .text
global main

; TODO: define functions and helper functions

next_string:    ;used to find the address of the next string
    push ebp    ;by searching for the next '\0'
    mov ebp, esp
    
    mov ecx, [ebp + 8]
    xor edx, edx
     
test_byte:              ;while current byte is different from '\0'
    mov dl, byte [ecx]  ;increment the address
    test dl, dl
    je end_next_string  ;found the '\0'

    inc ecx
    jmp test_byte
    
end_next_string:
    inc ecx
    
    leave
    ret
    
    
xor_strings:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    
    xor ecx, ecx
    xor edx, edx
    
copy_byte:              ;while current byte is different from '\0'
    mov cl, byte[eax]   ;xor it with the corresponding byte from the
    mov dl, byte[ebx]   ;other string, replace it inplace and incremetn
    test cl, cl         ;both addresses.
    je end_xor_strings  ;found the '\0'
    
xor_byte:
    xor cl, dl
    mov byte[eax], cl
    inc eax
    inc ebx
    jmp copy_byte
    
end_xor_strings:  
    leave
    ret
    
    
rolling_xor:
    push ebp
    mov ebp, esp
    
    mov ecx, [ebp + 8]
    xor eax, eax
    xor ebx, ebx
    xor edx, edx
    
    mov al, byte[ecx]
    
xor_byte_by_byte:       ;while the current byte differs from '\0'
    inc ecx             ;xor it with previous un-xored byte
    mov bl, byte[ecx]   ;and replace it inplace
    test bl, bl
    je end_rolling_xor  ;found the '\0'
    
    mov dl, bl
    xor dl, al
    mov byte[ecx], dl
    mov al, bl
    jmp xor_byte_by_byte
    
end_rolling_xor:   
    leave
    ret
    
    
xor_hex_strings:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    
    xor ecx, ecx
    xor edx, edx
    
copy_hex_byte:
    mov cl, byte[eax]
    mov dl, byte[ebx]
    
    test cl, cl
    je end_xor_hex_strings
    
xor_hex_byte:
    sub cl, 87
    sub dl, 87
    xor cl, dl
    mov byte[eax], cl
    inc eax
    inc ebx
    jmp copy_hex_byte
    
end_xor_hex_strings:    
    leave
    ret
    
    
hex_to_bin:
    push ebp
    mov ebp, esp
    
    mov ecx, [ebp + 8]          ;conver a string from hex to binary
                                ;convert 'a'-'f' to 10-15, convert '0'-'9'    
    xor eax, eax                ;to 0-9, shift it to the left by 4 bits,
    xor ebx, ebx                ;add the next byte, after converting it
    xor edx, edx                ;from a letter to a number, to the result,
                                ;thus transforming two bytes into one
test_byte_hex:
    mov al, byte [ecx + edx * 2]
    test al, al
    je end_hex_to_bin           ;while current byte is different form '\0'
    
    mov byte [ecx + edx * 2], 0 ;replace all unused bytes with '\0'
    
    cmp al, 'a'                 ;check if the byte is a letter or a digit
    jl is_digit_1
    
lower_case_1:                   ;it is a letter
    sub al, 'a'
    add al, 10
    jmp continue_1
    
is_digit_1:                     ;it is a digit
    sub al, '0'
    
continue_1:    
    add bl, al                  ;add it to the result
    shl bl, 4                   ;make room for the following byte
    
    mov al, byte [ecx + edx * 2 + 1]
    mov byte [ecx + edx * 2 + 1], 0
    
    cmp al, 'a'                 ;do the same for the second byte
    jl is_digit_2

lower_case_2:
    sub al, 'a'
    add al, 10
    jmp continue_2
    
is_digit_2:
    sub al, '0'
    
continue_2:  
    add bl, al
    
    mov byte [ecx + edx], bl    ;replace it inplace
    xor ebx, ebx                ;clear the container for the result
    inc edx 
    jmp test_byte_hex
    
end_hex_to_bin: ;inc ecx    
    leave
    ret
    
    
base32decode:               ;decode a string in base32
    push ebp                ;each byte is guaranteed to have at most
    mov ebp, esp            ;only the first 5 bits used
                            ;eax is a container where I put each bye
    mov ecx, [ebp + 8]      ;(in reality only its first 5 bits). when
                            ;I have more than 8 bits, I save those mose significant
    xor eax, eax            ;8 bits, I shift them out of eax and keep adding more bytes
    xor esi, esi            ;until I, again, have more than 8 bits, or I have
    xor edi, edi            ;reached the end of the string('\0' or '=')
    xor edx, edx
    xor ebx, ebx

while_not_enough:   
    mov dl, byte [ecx + edi]
    mov byte [ecx + edi], 0
    inc edi
    
    cmp dl, '='
    je last_byte
    cmp dl, 0
    je last_byte
    
    cmp dl, 'A'             ;conver 'A'-'Z' into 0-25
    jge letter
    
    sub dl, '2'             ;conver '2'-'7' into 26-31
    add dl, 26
    jmp continue_while
    
letter:
    sub dl, 'A'
    
continue_while:
    rol eax, 5   
    add eax, edx
    add bl, 5
        
    cmp bl, 8
    jl while_not_enough
    
    sub bl, 8
    xor bh, bh
    
ror_:
    cmp bh, bl
    je done_ror_
    ror eax, 1
    inc bh
    jmp ror_
    
done_ror_: 
    mov byte[ecx + esi], al
    inc esi
    and al, 0

    xor bh, bh
ret_rol_:
    cmp bh, bl
    je done_ret_rol_
    rol eax, 1
    inc bh
    jmp ret_rol_
    
done_ret_rol_:
    jmp while_not_enough
    
last_byte:
    mov byte[ecx + esi], al

    leave
    ret


find_substring:             ;used in searching for the string
    push ebp                ;"force" in the string decoded by
    mov ebp, esp            ;bruteforce
    xor eax, eax
    
source: 
    mov esi, [ebp + 8]      ;search for "force", starting
    mov edi, [ebp + 12]     ;at every index from 0 to the 
                            ;length of the bruteforce string
    add esi, eax
    repe cmpsb
    dec edi
do_not_inc:
    cmp byte[edi], 0
    jne continue
    xor eax, eax            ;if it is found, eax = 0
    
    leave
    ret
    
continue:
    inc eax
    
    cmp byte[esi], 0
    jne source
    
    mov eax, 1              ;if it is not found, eax = 1
    leave
    ret
    
    
xor_strings_singlebyte_xor:      ;xor every byte of the string
    push ebp                     ;with the key byte
    mov ebp, esp                 ;the function is similar to xor_strings
    mov ecx, [ebp + 8]
    mov eax, [ebp + 12]
    xor edx, edx
    xor ebx, ebx
    mov dl, byte[eax]
    
copy_byte_singlebyte_xor:
    mov bl, byte[ecx]
    
    test bl, bl
    je end_xor_strings_singlebyte_xor
    
xor_byte_singlebyte_xor:
    xor bl, dl
    mov byte[ecx], bl
    inc ecx
    jmp copy_byte_singlebyte_xor
    
end_xor_strings_singlebyte_xor:
    leave
    ret


bruteforce_singlebyte_xor:  ;bruteforce decode a string, coded
    push ebp                ;by xor-ing it with a byte
    mov ebp, esp
    
    mov ecx, [ebp + 8]
    mov eax, [ebp + 12]
        
while_less_than_ff:         ;generate every byte from 0x01 to 0xff
    inc dword[eax]          ;[eax] contains the key
    cmp dword[eax], dword 255
    jge end_bruteforce_singlebyte_xor
    push eax
    push ecx                ;decode the string by xor-ing
    call xor_strings_singlebyte_xor
    pop ecx
    pop eax
    
    lea edx, [eax - 6]      ;[eax - 6] contains "force"
    push eax
    push edx
    push ecx                ;check if it is the correct key,
    call find_substring     ;by searching for "force" in the
                            ;resulted string
    test eax, eax           ;if eax == 0, then it is the correct key
    je end_bruteforce_singlebyte_xor
    
    pop ecx
    pop edx
    pop eax
    
    push eax                ;if the key is not correct, xor it
    push ecx                ;again to reverse the changes
    call xor_strings_singlebyte_xor
    pop ecx
    pop eax
    
    jmp while_less_than_ff

end_bruteforce_singlebyte_xor:
    leave
    ret
     
create_tables:  ;create the two tables described in the readme
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    sub eax, 57
    xor edx, edx
    xor ecx, ecx
    mov dl, 'a'
create_first_table:
    mov byte[eax + ecx * 2], dl
    mov byte[eax + ecx * 2 + 1], ' '
    inc dl
    inc ecx
    cmp dl, 'z'
    jle create_first_table
    mov byte[eax + ecx * 2], ' '
    mov byte[eax + ecx * 2 + 1], ' '
    inc ecx
    mov byte[eax + ecx * 2], '.'
    mov byte[eax + ecx * 2 + 1], ' '
    inc ecx
    mov byte[eax + ecx * 2], 0
    
create_second_table:
    xor edx, edx
    add eax, 57
    xor ecx, ecx
    mov dl, 26
    mov byte[eax + ecx * 8], dl;' '
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'n'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 't'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'a'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'o'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 's'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'i'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'e'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'r'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'd'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'h'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'm'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'l'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'c'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'w'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'u'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 27
    mov byte[eax + ecx * 8], dl;'.'
    mov dword[eax + ecx * 8 + 4], 0 
    inc ecx
    mov dl, 'f'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'p'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'y'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'g'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'v'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'k'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'b'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'j'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'x'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'z'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    mov dl, 'q'
    sub dl, 'a'
    mov byte[eax + ecx * 8], dl
    mov dword[eax + ecx * 8 + 4], 0
    inc ecx
    
    leave
    ret
    
    
calc_frequencies:       ;for each letter in the string,
    push ebp            ;increment its appearance in
    mov ebp, esp        ;table 2
    
    mov ecx, [ebp + 8]
    mov eax, [ebp + 12]
    
    xor edx, edx
    xor ebx, ebx
    
while_have_bytes:
    xor edx, edx
    mov dl, byte[ecx + ebx]
    inc ebx
    
    cmp dl, 0
    je end_calc_frequencies
    
    cmp dl, ' '
    jne not_space
    
    mov dl, 26
    jmp continue_calc_frequencies
    
not_space:
    cmp dl, '.'
    jne not_comma
    
    mov dl, 27
    jmp continue_calc_frequencies
    
not_comma:
    sub dl, 'a'
 
continue_calc_frequencies:
    inc dword[eax + edx * 8 + 4]
    jmp while_have_bytes

end_calc_frequencies:       
    leave
    ret
    
    
update_tables:          ;create the substitution table(table 1)
    push ebp            ;the function is described in the readme
    
    mov ebp, esp
    mov eax, [ebp + 8]
    
    xor ecx, ecx
    xor edx, edx
    
while_first_table:
    mov ebx, -1
    xor edi, edi
    xor esi, esi
    
while_second_table:
    cmp ebx, [eax + edi * 8 + 4]
    jge continue_second_while
    
    mov ebx, [eax + edi * 8 + 4]
    mov esi, edi

continue_second_while:
    inc edi
    
    cmp edi, 28
    jl while_second_table

    mov [eax + esi * 8 + 4], dword -1
    
end_second_table:
    cmp ebx, -1                 ;were I to put cmp ebx, 0 here, every letter in
    je letters_does_not_change  ;the substitution table which does not have
                                ;woulld have the substitute '-'
    xor ebx, ebx
    mov bl, byte[eax + ecx * 8]
    mov edx, esi
    
    cmp dl, 27
    jne update_tabels_not_space
    
    mov dl, ' '
    jmp update_tables_continue
    
update_tabels_not_space:
    cmp dl, 26
    jne update_tabels_not_comma
    
    mov dl, '.'
    jmp update_tables_continue

update_tabels_not_comma:
    add dl, 'a'
    jmp update_tables_continue
    
letters_does_not_change:
    xor ebx, ebx
    mov bl, byte[eax + ecx * 8]
    mov dl, '-'

update_tables_continue:
    mov [eax + ebx * 2 - 56], dl
    sub eax, 57
    add eax, 57
    
    inc ecx
    
    cmp ecx, 28
    je end_update_tables
    
    jmp while_first_table
    
end_update_tables:
    leave
    ret
    
    
decode_substition:          ;decode the string
    push ebp
    mov ebp, esp
    
    mov ecx, [ebp + 8]
    mov eax, [ebp + 12]
    xor edx, edx
    xor ebx, ebx
    
while_still_have_bytes:     ;for each letter in the string,
    xor edx, edx            ;find its substitute in table 1
    mov dl, [ecx + ebx]     ;and replace it inplace with it
    cmp dl, 0
    je end_decode_substition
    
    push ebx
    push ecx
    push edx
    push eax
    call find_letter_substitute ;find the letter's substitute
    pop eax                     ;in table 1
    add esp, 4
    pop ecx
    pop ebx
    
    mov [ecx + ebx], dl
    
    inc ecx
    jmp while_still_have_bytes
    
end_decode_substition:
    leave
    ret

    
find_letter_substitute:     ;find a letter's substitute
    push ebp                ;in the substitution table
    mov ebp, esp
    
    mov eax, [ebp + 8]      ;compare the given letter
    mov edx, [ebp + 12]     ;with each letter in the table
                            ;if it is found, return it,
    xor ecx, ecx            ;else the letter stays the same
    
search_while:
    cmp dl, [eax + 2 * ecx - 56]
    je found_it
    inc ecx
    cmp ecx, 28
    jne search_while
    
    jmp end_find_letter_substitute
    
found_it:
    mov dl, [eax + 2 * ecx - 57]  
    
end_find_letter_substitute:    
    leave
    ret        
    

break_substitution:
    push ebp
    mov ebp, esp
    mov ecx, [ebp + 8]
    mov eax, [ebp + 12]
    
    pusha
    push eax
    call create_tables      ;create the two tables
    pop eax
    popa
    
    pusha
    push eax
    push ecx
    call calc_frequencies   ;find the frequencies of each letter
    pop ecx
    pop eax
    popa
    
    pusha
    push eax
    call update_tables      ;create the substitution table
    pop eax
    popa
    
    pusha
    push eax
    push ecx
    call decode_substition  ;decode the string
    pop ecx
    pop eax
    popa
    
    leave
    ret


main:
    push ebp
    mov ebp, esp
    sub esp, 2300
    sub esp, 10     ;reserved for the bruteforce task
    sub esp, 224    ;reserved for task 6's table 2
    sub esp, 57     ;reserved for task 6's table 1
    
    ; fd = open("./input.dat", O_RDONLY);
    mov eax, 5
    mov ebx, filename
    xor ecx, ecx
    xor edx, edx
    int 0x80
    
	; read(fd, ebp-2300, inputlen);
	mov ebx, eax
	mov eax, 3
	lea ecx, [ebp-2300]
	mov edx, [inputlen]
	int 0x80

	; close(fd);
	mov eax, 6
	int 0x80

	; all input.dat contents are now in ecx (address on stack)
        
	; TASK 1: Simple XOR between two byte streams
	; TODO: compute addresses on stack for str1 and str2
        push ecx; addr_str1
        
        push ecx
        call next_string;addr_str2 will be stored in ecx
        add esp, 4
        pop eax; addr_str1
        
	; TODO: XOR them byte by byte
	push ecx; addr_str2
        push eax; addr_str1
        call xor_strings
        pop eax
        pop ecx

	; Print the first resulting string
        push ecx
	push eax
        call puts
        add esp, 4
        pop ecx

	; TASK 2: Rolling XOR
	; TODO: compute address on stack for str3
        push ecx
        call next_string;addr_str3 will be stored in ecx
        add esp, 4
        
	; TODO: implement and apply rolling_xor function
        push ecx
	call rolling_xor
        pop ecx

	; Print the second resulting string
	push ecx
        call puts
        pop ecx

	; TASK 3: XORing strings represented as hex strings
	; TODO: compute addresses on stack for strings 4 and 5
        push ecx
        call next_string;addr_str4 will be stored in ecx
        add esp, 4
        
        push ecx; addr_str4
        
        push ecx
        call next_string;addr_str5 will be stored in ecx
        add esp, 4
        pop eax; addr_str4
        
        ;the unused bytes are replaced with '\0', and, due to
        ;the fact that I look for the next string by finding
        ;the first '\0', I have to look for addr_str6 before
        ;xor-ing the strings

        push eax
        push ecx
        call next_string;addr_str6 will be stored in ecx
        mov edx, ecx
        pop ecx
        pop eax
        
        push edx;save addr_str6 for task 5
        
        push eax
        push ecx
        call hex_to_bin;conver the strings from hex to binary
        pop ecx
        pop eax
        
        push ecx
        push eax
        call hex_to_bin
        pop eax
        pop ecx
                 
	; TODO: implement and apply xor_hex_strings
        push ecx; addr_str5
        push eax; addr_str4
        call xor_strings
        pop eax
        pop ecx

	; Print the third string
        push ecx
	push eax
        call puts
        add esp, 4
        pop ecx
	
	; TASK 4: decoding a base32-encoded string
	; TODO: compute address on stack for string 6
        pop edx
        mov ecx, edx
        push edx
        push ecx
        call next_string;addr_str7 will be stored in ecx
        add esp, 4
        pop edx
        push ecx; save addr_str7 for task 5
        
        mov ecx, edx
        
	; TODO: implement and apply base32decode
        push ecx
	call base32decode
        pop ecx

	; Print the fourth string
        push ecx
	call puts
        add esp, 4

	; TASK 5: Find the single-byte key used in a XOR encoding
	; TODO: determine address on stack for string 7
        pop ecx
	; TODO: implement and apply bruteforce_singlebyte_xor
        lea eax, [ebp-2310]
        mov [eax], dword "forc"
        lea eax, [ebp-2306]
        mov [eax], dword "e"
        lea eax, [ebp-2305]
        mov [eax], byte 0
        lea eax, [ebp-2304]
        mov [eax], dword 1
        ;I store the address for a null terminated "force" in eax - 6
        push eax
        push ecx
        call bruteforce_singlebyte_xor
        pop ecx
        pop eax

	; Print the fifth string and the found key value
        push eax
        push ecx
        call puts
        pop ecx
        pop eax

        push ecx
        
        mov edx, [eax]
        push edx
        push fmtstr
        call printf
        add esp, 8
        
        pop ecx

	; TASK 6: Break substitution cipher
	; TODO: determine address on stack for string 8
        push ecx
        call next_string;addr_str8 will be stored in ecx
        add esp, 4
        
	; TODO: implement break_substitution
        lea eax,[ebp - 2300 - 10 - 224] ;addr for table 2
        push eax                        ;table 1(the substitution
        push ecx                        ;table) is found at eax - 57
	call break_substitution
        pop ecx
        pop eax

	; Print final solution (after some trial and error)
        push eax
        push ecx
        call puts
        add esp, 4;goodbye ecx, you served me well
        pop eax

	; Print substitution table
        sub eax, 57
        push eax
        call puts
        add esp, 4;you too, eax. I will never forget you

	; Phew, finally done
    xor eax, eax
    leave
    ret
