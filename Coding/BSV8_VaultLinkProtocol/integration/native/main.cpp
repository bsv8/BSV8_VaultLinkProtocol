#define VLP_E2E_TEST_ONLY 1
#include "../esp32/demo.hpp"
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <unistd.h>
using namespace vaultlink;
namespace fs = std::filesystem;
// 原生端不是 ESP32 模拟器：直接执行与固件同一 Demo/SDK，真实 pipe + 原子文件 +
// mbedTLS。 仅用于独立实现互通检查；不得把此通过标记为 USB/Flash 真机通过。
Bytes read_file(const std::string &path) {
  if (!fs::exists(path))
    return {};
  std::ifstream f(path, std::ios::binary);
  require(bool(f), "storage-failed");
  Bytes b((std::istreambuf_iterator<char>(f)), {});
  require(b.size() <= 65536, "corrupt-state");
  return b;
}
void save_file(const std::string &path, const Bytes &b) {
  auto tmp = path + ".tmp";
  int fd = ::open(tmp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
  require(fd >= 0, "storage-failed");
  size_t at = 0;
  while (at < b.size()) {
    ssize_t n = ::write(fd, b.data() + at, b.size() - at);
    if (n <= 0) {
      ::close(fd);
      throw Failure("storage-failed");
    }
    at += n;
  }
  int rc = ::fsync(fd);
  int close_rc = ::close(fd);
  require(rc == 0 && close_rc == 0 && ::rename(tmp.c_str(), path.c_str()) == 0,
          "storage-failed");
  int dir = ::open(fs::path(path).parent_path().c_str(), O_RDONLY);
  require(dir >= 0, "storage-failed");
  rc = ::fsync(dir);
  ::close(dir);
  require(rc == 0, "storage-failed");
}
int random_bytes(void *, unsigned char *out, size_t n) {
  int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;
  size_t at = 0;
  while (at < n) {
    auto k = ::read(fd, out + at, n - at);
    if (k <= 0) {
      ::close(fd);
      return -1;
    }
    at += k;
  }
  ::close(fd);
  return 0;
}
class Files : public Store {
  std::string path;
  bool fail = false;

public:
  explicit Files(std::string p) : path(std::move(p)) {}
  Bytes load() override { return read_file(path); }
  void save(const Bytes &b) override {
    if (fail) {
      fail = false;
      throw Failure("storage-injected-failure");
    }
    save_file(path, b);
  }
  void reject() { fail = true; }
};
class Platform : public vlp_e2e::Platform {
  std::string dir;
  Files store;

public:
  explicit Platform(std::string d) : dir(d), store(d + "/policy") {
    fs::create_directories(dir);
  }
  Store &policy_store() override { return store; }
  Bytes load_plan() override { return read_file(dir + "/plan"); }
  void save_plan(const Bytes &b) override { save_file(dir + "/plan", b); }
  void clear_policy() override { save_file(dir + "/policy", {}); }
  void reject_next_write() override { store.reject(); }
  void restart() override { ::_exit(75); }
  uint32_t boot() {
    auto b = read_file(dir + "/boot");
    uint64_t n = b.empty() ? 0 : decode(b).integer();
    require(n < UINT32_MAX, "run-exhausted");
    save_file(dir + "/boot", encode(Value(++n)));
    return uint32_t(n);
  }
};
class PipeTransport : public ByteTransport {
  std::chrono::steady_clock::time_point start =
      std::chrono::steady_clock::now();

public:
  bool eof = false;
  PipeTransport() {
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    require(flags >= 0 && fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == 0,
            "transport-failed");
  }
  int read_byte() override {
    uint8_t b;
    auto n = ::read(STDIN_FILENO, &b, 1);
    if (n == 1)
      return b;
    if (n == 0)
      eof = true;
    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
      throw Failure("transport-failed");
    return -1;
  }
  void write(const Bytes &b) override {
    size_t at = 0;
    while (at < b.size()) {
      auto n = ::write(STDOUT_FILENO, b.data() + at, b.size() - at);
      require(n > 0, "transport-failed");
      at += n;
    }
  }
  uint64_t millis() override {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
  }
};
int main(int argc, char **argv) {
  try {
    require(argc == 2, "state-directory-required");
    Platform platform(argv[1]);
    uint32_t run = platform.boot();
    Bytes private_key(32);
    private_key[31] = 1;
    IdentityKey identity(private_key, random_bytes);
    std::fill(private_key.begin(), private_key.end(), 0);
    vlp_e2e::Demo demo(platform, identity);
    PipeTransport transport;
    Endpoint endpoint(
        transport, identity, random_bytes, run,
        [&](const std::string &op, const Value &b, const Bytes &c) {
          return demo.prepare(op, b, c);
        },
        [&] { demo.disconnected(); },
        [](const std::string &) {
          return true;
        }); // 仅公开测试密钥的无人值守配对。
    endpoint.set_test_control(
        [&](const std::string &op, const Value &b, const Bytes &c) {
          return demo.control(op, b, c);
        });
    while (!transport.eof) {
      endpoint.poll();
      demo.tick();
      usleep(1000);
    }
    endpoint.reset();
    return 0;
  } catch (const std::exception &e) {
    fprintf(stderr, "native SDK failure: %s\n", e.what());
    return 1;
  }
}
