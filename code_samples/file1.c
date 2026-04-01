#include <stdio.h>
#include <stdlib.h>

void process_user_command() {
    char command[256];
    char user_input[100];

    // SOURCE: Reading untru\\\\sted user input
    printf("Enter filename to delete: ");
    gets(user_input); 

    // VULNERABILITY: Constructing a command blindly
    sprintf(command, "rm %s", user_input);

    // SINK: Executing the command
    // If user types "; rm -rf /", the system dies.
    system(command);
}