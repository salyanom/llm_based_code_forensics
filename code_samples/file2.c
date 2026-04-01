#include <string.h>
#include <stdio.h>

void copy_name(char *user_name) {
    char buffer[10]; // Tiny buffer (size 10)

    // SINK + SOURCE combined
    // strcpy doesn't check size. If user_name is 20 chars, this crashes.
    strcpy(buffer, user_name);
    
    printf("Hello %s\n", buffer);
}