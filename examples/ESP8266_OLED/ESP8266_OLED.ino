// ESP8266 example: receive encrypted FCM messages, parse rupiah amount from
// notification body, and display it on a 128x64 SSD1306 OLED with full status
// feedback (booting, WiFi connecting/connected/reconnect, FCM status, idle,
// transaction amount, errors).
//
// Display states:
//   - "Booting..." on power-up
//   - "WiFi: connecting" while WiFi.begin() is connecting
//   - "WiFi: <ip>" briefly after WiFi connects
//   - "Menunggu transaksi" while idle
//   - "Saldo diterima" + large amount for 4 seconds after each notification
//   - error messages (FCM init fail, no nominal, decrypt fail, etc.) shown
//     transiently on top of the idle screen
//   - "WiFi: reconnecting" if WiFi drops between MCS reconnects
//
// Build flags expected (platformio.ini):
//   -D FCM_REQUIRE_PREGENERATED_CREDENTIALS=1
//   -D FCM_DECRYPT_VIA_SERVER=1
//
// Library deps:
//   adafruit/Adafruit GFX Library
//   adafruit/Adafruit SSD1306

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <FCMReceiver.h>

#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASS       "YOUR_WIFI_PASSWORD"
#define FCM_DECRYPT_API "http://your-worker.example.com/api/decrypt"

#define SCREEN_WIDTH   128
#define SCREEN_HEIGHT  64
#define OLED_RESET     -1
#define OLED_ADDR      0x3C
#define SDA_PIN        5
#define SCL_PIN        4

#define AMOUNT_HOLD_MS   4000
#define ERROR_HOLD_MS    3000

static Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

enum FcmUiState {
    UI_BOOT,
    UI_WIFI,
    UI_IDLE,
    UI_AMOUNT,
    UI_ERROR
};

static FcmUiState s_ui_state = UI_BOOT;
static uint32_t   s_state_since = 0;
static char       s_status_line[32] = "Booting";
static uint64_t   s_amount = 0;
static char       s_error_line[32] = "";

static void render(void);

static void set_status(const char *line) {
    snprintf(s_status_line, sizeof(s_status_line), "%s", line);
    render();
}

static void show_idle(void) {
    s_ui_state = UI_IDLE;
    s_state_since = millis();
    render();
}

static void show_amount(uint64_t amount) {
    s_amount = amount;
    s_ui_state = UI_AMOUNT;
    s_state_since = millis();
    render();
}

static void show_error(const char *msg) {
    snprintf(s_error_line, sizeof(s_error_line), "%s", msg);
    s_ui_state = UI_ERROR;
    s_state_since = millis();
    render();
}

static void format_rupiah(uint64_t amount, char *out, size_t out_len) {
    char digits[24];
    int n = snprintf(digits, sizeof(digits), "%llu", (unsigned long long)amount);
    if (n <= 0) {
        snprintf(out, out_len, "Rp0");
        return;
    }
    char buf[40];
    int oi = 0;
    buf[oi++] = 'R';
    buf[oi++] = 'p';
    int first_group = n % 3;
    if (first_group == 0) first_group = 3;
    int di = 0;
    for (int i = 0; i < first_group && oi < (int)sizeof(buf) - 1; i++) {
        buf[oi++] = digits[di++];
    }
    while (di < n && oi < (int)sizeof(buf) - 2) {
        buf[oi++] = '.';
        for (int i = 0; i < 3 && di < n && oi < (int)sizeof(buf) - 1; i++) {
            buf[oi++] = digits[di++];
        }
    }
    buf[oi] = '\0';
    snprintf(out, out_len, "%s", buf);
}

static int pick_text_size(const char *text) {
    int len = strlen(text);
    for (int size = 3; size >= 1; size--) {
        if (len * 6 * size <= SCREEN_WIDTH) return size;
    }
    return 1;
}

static void render(void) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);

    display.setTextSize(1);
    display.setCursor(0, 0);
    display.print(s_status_line);
    display.drawFastHLine(0, 10, SCREEN_WIDTH, SSD1306_WHITE);

    switch (s_ui_state) {
        case UI_BOOT:
            display.setCursor(0, 24);
            display.print("Booting...");
            break;
        case UI_WIFI:
            display.setCursor(0, 24);
            display.print("Hubungkan WiFi");
            break;
        case UI_IDLE:
            display.setTextSize(1);
            display.setCursor(0, 26);
            display.print("Menunggu");
            display.setCursor(0, 38);
            display.print("transaksi...");
            break;
        case UI_AMOUNT: {
            display.setTextSize(1);
            display.setCursor(0, 14);
            display.print("Saldo diterima");
            char formatted[40];
            format_rupiah(s_amount, formatted, sizeof(formatted));
            int size = pick_text_size(formatted);
            display.setTextSize(size);
            int text_w = strlen(formatted) * 6 * size;
            int text_h = 8 * size;
            int x = (SCREEN_WIDTH - text_w) / 2;
            if (x < 0) x = 0;
            int y = 26 + ((SCREEN_HEIGHT - 26) - text_h) / 2;
            display.setCursor(x, y);
            display.print(formatted);
            break;
        }
        case UI_ERROR:
            display.setCursor(0, 18);
            display.print("Error:");
            display.setCursor(0, 32);
            display.print(s_error_line);
            display.setCursor(0, 52);
            display.print("(menunggu lagi)");
            break;
    }
    display.display();
}

static void on_fcm_status(fcm_status_t status) {
    switch (status) {
        case FCM_STATUS_CONNECTING:  set_status("FCM: connecting"); break;
        case FCM_STATUS_CONNECTED:   set_status("FCM: online"); break;
        case FCM_STATUS_DISCONNECTED: set_status("FCM: offline"); break;
        case FCM_STATUS_AUTH_FAILED: set_status("FCM: auth fail"); break;
    }
}

static const fcm_config_t fcm_cfg = {
    .android_id      = 0000000000000000000ULL,
    .security_token  = 0000000000000000000ULL,
    .fcm_token       = "YOUR_FCM_TOKEN",
    .private_key_b64 = "YOUR_PKCS8_PRIVATE_KEY_BASE64",
    .auth_secret_b64 = "YOUR_AUTH_SECRET_BASE64",
    .auto_reconnect  = false,
    .status_cb = on_fcm_status,
    .decrypt_api_url = FCM_DECRYPT_API
};

static bool parse_rupiah_amount(const char *body, uint64_t *out_amount) {
    if (!body || !out_amount) return false;
    const char *p = body;
    while (*p) {
        if ((p[0] == 'r' || p[0] == 'R') && (p[1] == 'p' || p[1] == 'P')) {
            const char *q = p + 2;
            while (*q == ' ' || *q == '\t') q++;
            uint64_t value = 0;
            int digits = 0;
            while (*q) {
                if (*q >= '0' && *q <= '9') {
                    value = value * 10 + (uint64_t)(*q - '0');
                    digits++;
                } else if (*q == '.') {
                    // skip thousand separator
                } else {
                    break;
                }
                q++;
            }
            if (digits >= 2) {
                *out_amount = value;
                return true;
            }
        }
        p++;
    }
    return false;
}

static void on_message(const fcm_message_t *msg) {
    const char *body = NULL;
    if (msg->notif_data && msg->notif_data->body[0]) {
        body = msg->notif_data->body;
    } else if (msg->json_data) {
        body = msg->json_data;
    }
    if (!body) {
        show_error("Pesan kosong");
        return;
    }

    Serial.printf("[FCM] body: %s\n", body);
    uint64_t amount = 0;
    if (parse_rupiah_amount(body, &amount)) {
        show_amount(amount);
    } else {
        show_error("Tanpa nominal");
    }
}

static bool ensure_wifi(void) {
    if (WiFi.status() == WL_CONNECTED) return true;
    set_status("WiFi: reconnecting");
    s_ui_state = UI_WIFI;
    s_state_since = millis();
    render();
    WiFi.reconnect();
    uint32_t deadline = millis() + 30000;
    while (WiFi.status() != WL_CONNECTED && millis() < deadline) {
        delay(500);
        yield();
    }
    if (WiFi.status() != WL_CONNECTED) {
        set_status("WiFi: failed");
        return false;
    }
    char line[32];
    snprintf(line, sizeof(line), "WiFi: %s", WiFi.localIP().toString().c_str());
    set_status(line);
    return true;
}

void setup() {
    system_update_cpu_freq(160);
    Serial.begin(115200);
    delay(500);

    Wire.begin(SDA_PIN, SCL_PIN);
    if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
        Serial.println("SSD1306 init failed");
    }
    s_ui_state = UI_BOOT;
    s_state_since = millis();
    set_status("Booting");

    s_ui_state = UI_WIFI;
    set_status("WiFi: connecting");
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        yield();
    }
    char line[32];
    snprintf(line, sizeof(line), "WiFi: %s", WiFi.localIP().toString().c_str());
    set_status(line);
    Serial.printf("\nWiFi: %s\n", WiFi.localIP().toString().c_str());

    if (fcm_init(&fcm_cfg) != ESP_OK) {
        show_error("FCM init gagal");
        return;
    }
    Serial.print("FCM Token: ");
    Serial.println(fcm_get_token());
    show_idle();
}

void loop() {
    if (s_ui_state == UI_AMOUNT && millis() - s_state_since > AMOUNT_HOLD_MS) {
        show_idle();
    }
    if (s_ui_state == UI_ERROR && millis() - s_state_since > ERROR_HOLD_MS) {
        show_idle();
    }

    if (!ensure_wifi()) {
        delay(2000);
        return;
    }

    fcm_start(on_message);
    delay(500);
}
