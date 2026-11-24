/*
 * lidar-efr32: drive the Echo Plus 2nd Gen EFR32 radio from the SoC.
 *
 * Subcommands:
 *   run                 leave the Gecko bootloader, start the application and
 *                       hold RESET_N high until the process is killed
 *   flash <file.gbl>    upload a GBL through the bootloader's XMODEM upload
 *   version             ask the running application for its Spinel NCP version
 *
 * RESET_N has no pull-up: closing the GPIO handle returns the line to input
 * and holds the chip in reset, so `run` must stay alive for as long as the
 * application should keep running (lab-notes/phase-06/hw-20261121/step25-efr32/
 * result.md in https://github.com/TomGrozev/libreecho-lidar-port).  `version`
 * therefore touches the UART only, so it works while that holder owns the
 * lines.
 *
 * The radio shares uart2 with the EFR32's Gecko bootloader.  It runs without
 * hardware flow control; the lab proved both the bootloader menu and the
 * OpenThread RCP on this port with crtscts off
 * (lab-notes/phase-06/hw-20261121/step25-efr32/result.md in
 * https://github.com/TomGrozev/libreecho-lidar-port).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/gpio.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#define SWCLK_LINE 1
#define RESET_LINE 13
#define BOOTLOADER_BANNER "BL >"
#define BOOTLOADER_PROBES 3

#define XMODEM_ACK 0x06
#define XMODEM_NAK 0x15
#define XMODEM_CAN 0x18
#define XMODEM_RETRIES 10

static int chip_fd = -1;
static int swclk_fd = -1;
static int reset_fd = -1;
static int uart_fd = -1;

static void die(const char *what) {
    fprintf(stderr, "lidar-efr32: %s: %s\n", what, strerror(errno));
    exit(1);
}

/*
 * Both lines are requested high.  RESET_N has no pull-up and SWCLK low parks
 * the chip in its bootloader, so a request at the kernel's default of 0 would
 * reset the radio on every subcommand, including the `version` probe.
 */
static int request_line(unsigned int line) {
    struct gpiohandle_request req;
    memset(&req, 0, sizeof(req));
    req.lineoffsets[0] = line;
    req.lines = 1;
    req.flags = GPIOHANDLE_REQUEST_OUTPUT;
    req.default_values[0] = 1;
    strncpy(req.consumer_label, "lidar-efr32", sizeof(req.consumer_label) - 1);
    if (ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &req) < 0)
        return -1;
    return req.fd;
}

static void gpio_set(int fd, int value) {
    struct gpiohandle_data data;
    memset(&data, 0, sizeof(data));
    data.values[0] = value ? 1 : 0;
    if (ioctl(fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data) < 0)
        die("gpio set");
}

static void hold_lines(void) {
    /* Closing either handle returns the line to input; RESET_N has no pull-up,
     * so the chip would drop into reset.  Stay alive with both held high. */
    for (;;)
        pause();
}

static void open_gpio(void) {
    chip_fd = open("/dev/gpiochip0", O_RDONLY | O_CLOEXEC);
    if (chip_fd < 0)
        die("open /dev/gpiochip0");
    swclk_fd = request_line(SWCLK_LINE);
    if (swclk_fd < 0)
        die("request EFR32_SWCLK");
    reset_fd = request_line(RESET_LINE);
    if (reset_fd < 0)
        die("request EFR32_RESET_N");
}

static void open_uart(void) {
    struct termios tio;
    uart_fd = open("/dev/ttyS2", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (uart_fd < 0)
        die("open /dev/ttyS2");
    if (tcgetattr(uart_fd, &tio) < 0)
        die("tcgetattr");
    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tio.c_iflag &= ~(IXON | IXOFF);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 1;
    if (tcsetattr(uart_fd, TCSANOW, &tio) < 0)
        die("tcsetattr");
    tcflush(uart_fd, TCIOFLUSH);
}

static int read_byte(int timeout_ms) {
    struct pollfd pfd = {.fd = uart_fd, .events = POLLIN};
    unsigned char byte;
    int ready = poll(&pfd, 1, timeout_ms);
    if (ready <= 0)
        return -1;
    if (read(uart_fd, &byte, 1) != 1)
        return -1;
    return byte;
}

static void write_all(const void *data, size_t size) {
    const unsigned char *cursor = data;
    while (size) {
        ssize_t written = write(uart_fd, cursor, size);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            die("uart write");
        }
        cursor += written;
        size -= (size_t)written;
    }
}

static void reset_chip(int bootloader) {
    gpio_set(swclk_fd, bootloader ? 0 : 1);
    usleep(300000);
    gpio_set(reset_fd, 0);
    usleep(100000);
    gpio_set(reset_fd, 1);
    usleep(bootloader ? 700000 : 1500000);
}

static int bootloader_answers(void) {
    char buffer[128];
    size_t used = 0;
    usleep(200000);
    write_all("\r", 1);
    for (int i = 0; i < 40; i++) {
        int byte = read_byte(100);
        if (byte < 0)
            continue;
        if (used + 1 < sizeof(buffer))
            buffer[used++] = (char)byte;
    }
    buffer[used] = '\0';
    return strstr(buffer, BOOTLOADER_BANNER) != NULL;
}

static uint16_t crc16_ccitt(const unsigned char *data, size_t size) {
    uint16_t crc = 0;
    for (size_t i = 0; i < size; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int bit = 0; bit < 8; bit++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

/* 0 on `expected`, 1 on NAK, -1 on CAN or timeout. */
static int wait_for(unsigned char expected, int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited += 10) {
        int byte = read_byte(10);
        if (byte == expected)
            return 0;
        if (byte == XMODEM_NAK)
            return 1;
        if (byte == XMODEM_CAN)
            return -1;
    }
    return -1;
}

static int send_until_ack(const unsigned char *data, size_t size) {
    for (int attempt = 0; attempt < XMODEM_RETRIES; attempt++) {
        write_all(data, size);
        int answer = wait_for(XMODEM_ACK, 10000);
        if (answer <= 0)
            return answer;
    }
    return -1;
}

static int xmodem_send(const unsigned char *data, size_t size) {
    unsigned char frame[3 + 128 + 2];
    uint8_t sequence = 1;
    size_t offset = 0;
    if (wait_for('C', 10000) != 0)
        return -1;
    while (offset < size) {
        size_t chunk = size - offset < 128 ? size - offset : 128;
        memset(frame, 0x1a, sizeof(frame));
        frame[0] = 0x01;
        frame[1] = sequence;
        frame[2] = (unsigned char)~sequence;
        memcpy(frame + 3, data + offset, chunk);
        uint16_t crc = crc16_ccitt(frame + 3, 128);
        frame[131] = (unsigned char)(crc >> 8);
        frame[132] = (unsigned char)(crc & 0xff);
        if (send_until_ack(frame, sizeof(frame)) != 0)
            return -1;
        offset += chunk;
        sequence++;
    }
    return send_until_ack((const unsigned char *)"\x04", 1);
}

static unsigned char *read_file(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    unsigned char *data;
    long length;
    if (!file)
        die(path);
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0)
        die("read firmware");
    data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, file) != (size_t)length)
        die("read firmware");
    fclose(file);
    *size = (size_t)length;
    return data;
}

static void exchange(const unsigned char *frame, size_t size, int seconds) {
    write_all(frame, size);
    for (int waited = 0; waited < seconds * 100; waited++) {
        int byte = read_byte(20);
        if (byte < 0)
            continue;
        printf("%02x", byte);
        fflush(stdout);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s run|flash <file.gbl>|version\n", argv[0]);
        return 2;
    }
    open_uart();
    if (strcmp(argv[1], "run") == 0) {
        open_gpio();
        reset_chip(0);
        hold_lines();
        return 0;
    }
    if (strcmp(argv[1], "version") == 0) {
        /* Spinel PROP_VALUE_GET NCP_VERSION, TID 2.  UART only: the `run`
         * holder owns both control lines for as long as the application
         * should stay out of reset. */
        static const unsigned char frame[] = {0x7e, 0x81, 0x02, 0x02, 0x8e, 0x80, 0x7e};
        exchange(frame, sizeof(frame), 2);
        return 0;
    }
    if (strcmp(argv[1], "flash") == 0 && argc == 3) {
        size_t size = 0;
        unsigned char *data = read_file(argv[2], &size);
        int answered = 0;
        open_gpio();
        for (int probe = 0; probe < BOOTLOADER_PROBES && !answered; probe++) {
            reset_chip(1);
            answered = bootloader_answers();
        }
        if (!answered) {
            fprintf(stderr, "lidar-efr32: the bootloader does not answer\n");
            return 1;
        }
        write_all("1", 1);
        if (xmodem_send(data, size) < 0) {
            fprintf(stderr, "lidar-efr32: upload failed\n");
            return 1;
        }
        free(data);
        reset_chip(0);
        return 0;
    }
    fprintf(stderr, "usage: %s run|flash <file.gbl>|version\n", argv[0]);
    return 2;
}
