#pragma once
#include "endpoint.hpp"
#ifdef ARDUINO
#include <Arduino.h>
#include <esp_timer.h>
namespace vaultlink {
// USB-UART 板与原生 CDC 均挂载流；不使用无线栈，也不在协议串口写文本日志。
class ArduinoSerialTransport final : public ByteTransport {
  Stream &stream;

public:
  explicit ArduinoSerialTransport(Stream &s) : stream(s) {}
  int read_byte() override { return stream.available() ? stream.read() : -1; }
  void write(const Bytes &b) override {
    require(stream.write(b.data(), b.size()) == b.size(),
            "transport-write-failed");
    stream.flush();
  }
  uint64_t millis() override { return uint64_t(esp_timer_get_time()) / 1000; }
};
} // namespace vaultlink
#endif
