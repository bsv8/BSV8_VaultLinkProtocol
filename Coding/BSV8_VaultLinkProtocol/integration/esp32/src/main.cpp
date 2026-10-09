#include "../../../device/sdk/arduino_serial.hpp"
#include "../demo.hpp"
#include <Arduino.h>
#include <bootloader_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <nvs.h>
#include <nvs_flash.h>
using namespace vaultlink;
namespace {
void nvs_check(esp_err_t rc) { require(rc == ESP_OK, "storage-failed"); }
int random_bytes(void *, unsigned char *out, size_t n) {
  esp_fill_random(out, n);
  return 0;
}
class NvsStore : public Store {
  nvs_handle_t handle;
  bool fail = false;

public:
  explicit NvsStore(nvs_handle_t h) : handle(h) {}
  Bytes load() override {
    size_t n = 0;
    auto rc = nvs_get_blob(handle, "policy", nullptr, &n);
    if (rc == ESP_ERR_NVS_NOT_FOUND)
      return {};
    nvs_check(rc);
    require(n <= 65536, "corrupt-state");
    Bytes b(n);
    nvs_check(nvs_get_blob(handle, "policy", b.data(), &n));
    return b;
  }
  void save(const Bytes &b) override {
    if (fail) {
      fail = false;
      throw Failure("storage-injected-failure");
    }
    nvs_check(nvs_set_blob(handle, "policy", b.data(), b.size()));
    nvs_check(nvs_commit(handle));
  }
  void reject() { fail = true; }
};
class EspPlatform : public vlp_e2e::Platform {
  nvs_handle_t handle;
  NvsStore store;

public:
  explicit EspPlatform(nvs_handle_t h) : handle(h), store(h) {}
  Store &policy_store() override { return store; }
  Bytes load_plan() override {
    size_t n = 0;
    auto rc = nvs_get_blob(handle, "fault", nullptr, &n);
    if (rc == ESP_ERR_NVS_NOT_FOUND)
      return {};
    nvs_check(rc);
    require(n <= 256, "corrupt-plan");
    Bytes b(n);
    nvs_check(nvs_get_blob(handle, "fault", b.data(), &n));
    return b;
  }
  void save_plan(const Bytes &b) override {
    if (b.empty()) {
      auto rc = nvs_erase_key(handle, "fault");
      require(rc == ESP_OK || rc == ESP_ERR_NVS_NOT_FOUND, "storage-failed");
    } else
      nvs_check(nvs_set_blob(handle, "fault", b.data(), b.size()));
    nvs_check(nvs_commit(handle));
  }
  void clear_policy() override {
    auto rc = nvs_erase_key(handle, "policy");
    require(rc == ESP_OK || rc == ESP_ERR_NVS_NOT_FOUND, "storage-failed");
    nvs_check(nvs_commit(handle));
  }
  void reject_next_write() override { store.reject(); }
  void restart() override { esp_restart(); }
};
std::unique_ptr<EspPlatform> platform;
std::unique_ptr<IdentityKey> identity;
std::unique_ptr<vlp_e2e::Demo> demo;
std::unique_ptr<ArduinoSerialTransport> transport;
std::unique_ptr<Endpoint> endpoint;
} // namespace
void setup() {
  Serial.begin(115200);
  try {
    // E2E 只使用公开标量 1，绝不读取钱包 NVS。其独立命名空间为 vlp_e2e。
    nvs_check(nvs_flash_init());
    nvs_handle_t handle;
    nvs_check(nvs_open("vlp_e2e", NVS_READWRITE, &handle));
    uint32_t run = 0;
    auto rc = nvs_get_u32(handle, "boot", &run);
    require(rc == ESP_OK || rc == ESP_ERR_NVS_NOT_FOUND, "storage-failed");
    require(run < UINT32_MAX, "run-exhausted");
    ++run;
    nvs_check(nvs_set_u32(handle, "boot", run));
    nvs_check(nvs_commit(handle));
    // 无 WiFi/BT 时启用 ESP32 内部熵源，不以伪随机代替密钥协商随机数。
    bootloader_random_enable();
    Bytes key(32);
    key[31] = 1;
    identity = std::make_unique<IdentityKey>(key, random_bytes);
    std::fill(key.begin(), key.end(), 0);
    platform = std::make_unique<EspPlatform>(handle);
    demo = std::make_unique<vlp_e2e::Demo>(*platform, *identity);
    transport = std::make_unique<ArduinoSerialTransport>(Serial);
    endpoint = std::make_unique<Endpoint>(
        *transport, *identity, random_bytes, run,
        [](const std::string &op, const Value &body, const Bytes &hash) {
          return demo->prepare(op, body, hash);
        },
        [] { demo->disconnected(); },
        [](const std::string &) {
          return true;
        }); // E2E 专用自动配对，产品需实体决定。
    endpoint->set_test_control(
        [](const std::string &op, const Value &body, const Bytes &hash) {
          return demo->control(op, body, hash);
        });
  } catch (...) {
    endpoint.reset(); /* 初始化失败保持不可用，禁止打印帧内假成功。 */
  }
}
void loop() {
  if (endpoint) {
    try {
      endpoint->poll();
      demo->tick();
    } catch (...) {
      endpoint->reset();
    }
  }
  delay(1);
}
