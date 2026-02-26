# FCMReceiver Arduino Library

A Firebase Cloud Messaging (FCM) receiver library for ESP32 and ESP8266. This library allows your ESP device to receive real-time push messages directly from FCM via the MCS (Mobile Connection Server) protocol with WebPush `aesgcm` decryption.

## Features
- Connects directly to FCM using the Mobile Connection Server (MCS) protocol.
- Supports receiving encrypted WebPush notifications (`aesgcm`).
- Designed to run efficiently on ESP32 (and compatible with ESP8266).
- Low memory footprint compared to keeping a constant HTTP long-polling connection open.
- Runs in a dedicated FreeRTOS task (on ESP32).

## Installation

### PlatformIO
Add the following to your `platformio.ini`:
```ini
[env:my_board]
lib_deps =
  https://github.com/agusibrahim/esp-fcm-arduino.git
```

### Arduino IDE
1. Download this repository as a `.zip` file from the top right.
2. In the Arduino IDE, go to **Sketch > Include Library > Add .ZIP Library...**
3. Select the downloaded `.zip` file.

## Usage & Requirements

To use this library, you **must** obtain valid FCM device credentials:
- `android_id`
- `security_token`
- `fcm_token`
- `app_id`
- `private_key` (Base64 PKCS8 DER)
- `auth_secret` (Base64URL)

Check the [BasicReceive example](./examples/BasicReceive/BasicReceive.ino) to see how to define the configuration struct and start receiving notifications.

## Dependencies
- `WiFi`
- `WiFiClientSecure`

## License
MIT
