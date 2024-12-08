#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CPUINFO_PATH "/proc/cpuinfo"

// Function to read and display CPU information
void display_cpu_info() {
    FILE *file = fopen(CPUINFO_PATH, "r");
    if (file == NULL) {
        perror("Failed to open cpuinfo file");
        return;
    }

    char line[256];
    int cpu_count = 0;

    // Loop through each line in the cpuinfo file
    while (fgets(line, sizeof(line), file)) {
        // Print CPU details, separating by processor
        if (strncmp(line, "processor", 8) == 0) {
            if (cpu_count > 0) {
                printf("\n");
            }
            printf("Processor %d:\n", cpu_count++);
        }

        // Print the line containing CPU information
        printf("%s", line);
    }

    fclose(file);
}

int main() {
    printf("Processor Information:\n");
    printf("=======================\n");

    // Display CPU information
    display_cpu_info();

    return 0;
}

