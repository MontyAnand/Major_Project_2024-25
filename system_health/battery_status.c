#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BATTERY_PATH "/sys/class/power_supply/BAT0/"  // Change if necessary

// Function to read a value from a file
int read_value(const char *file_path, char *buffer, size_t buffer_size) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }
    
    if (fgets(buffer, buffer_size, file) == NULL) {
        perror("fgets");
        fclose(file);
        return -1;
    }
    
    fclose(file);
    return 0;
}

// Function to get battery information
void get_battery_info() {
    char buffer[256];

    // Read battery status
    if (read_value(BATTERY_PATH "status", buffer, sizeof(buffer)) == 0) {
        printf("Battery Status: %s", buffer);
    }

    // Read battery capacity
    if (read_value(BATTERY_PATH "capacity", buffer, sizeof(buffer)) == 0) {
        printf("Battery Capacity: %s%%\n", buffer);
    }

    // Read battery voltage
    if (read_value(BATTERY_PATH "voltage_now", buffer, sizeof(buffer)) == 0) {
        printf("Battery Voltage: %.2f V\n", atof(buffer) / 1e6); // Convert from microvolts
    }

    // Read battery energy
    if (read_value(BATTERY_PATH "energy_now", buffer, sizeof(buffer)) == 0) {
        printf("Battery Energy: %.2f Wh\n", atof(buffer) / 3.6e6); // Convert from microWh
    }

    // Read battery temperature
    if (read_value(BATTERY_PATH "temp", buffer, sizeof(buffer)) == 0) {
        printf("Battery Temperature: %.1f °C\n", atof(buffer) / 10); // Convert from tenths of degree Celsius
    }

    // Read cycle count (if available)
    if (read_value(BATTERY_PATH "cycle_count", buffer, sizeof(buffer)) == 0) {
        printf("Battery Cycle Count: %s\n", buffer);
    } else {
        printf("Cycle Count: Not Available\n");
    }
}

int main() {
    printf("Battery Monitoring Information:\n");
    printf("===============================\n");
    
    get_battery_info();
    
    return 0;
}

