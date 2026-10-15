# RocKey 产品 E2E

此入口不同于 `integration:hardware` 的 SDK 示例固件测试，执行真实 RocKey 产品 App 与 Keymaster Worker 适配器。设计及人工门禁见 [需求与施工单](../../../../docs/产品E2E设计与施工单.md)。

在 `VaultLinkProtocol/Coding/BSV8_VaultLinkProtocol` 运行：

```sh
npm run integration:rockey:prepare
npm run integration:rockey:smoke
npm run integration:rockey:list
VLP_SERIAL_PORT=/dev/cu.usbserial-实际端口 npm run integration:rockey:flash
# 已刷入匹配的产品测试固件，仅跑真机测试：
VLP_SERIAL_PORT=/dev/cu.usbserial-实际端口 npm run integration:rockey
```

仅用户明确确认空的专用测试设备，才在首次刷写时初始化文件系统：

```sh
VLP_SERIAL_PORT=/dev/cu.usbserial-实际端口 npm run integration:rockey:flash -- --initialize-empty-test-device
```

参数：`VLP_ROCKEY_ROOT`、`VLP_KEYMASTER_ROOT` 指定两个仓库；`ROCKEY_PYTHON` 指定带 PlatformIO/pyserial 的 Python；`ROCKEY_E2E_ENV=m5stack-core-e2e-zh-hans` 选择中文；`ROCKEY_NM` 指定发布扫描工具；`ROCKEY_BACKUP_DIR` 指定仓库外私有备份位置；浏览器沿用 `VLP_BROWSER_EXECUTABLE`/`VLP_BROWSER_CHANNEL`。

USB 权限只写一次性浏览器资料目录。只连接一台目标串口桥，避免相同 VID/PID 选错。浏览器失败会保留 trace/截图；机器报告在 `integration/artifacts/rockey-product-hardware-report.json`。`expectedFirmwareSHA256` 是本机预期构建文件，不冒充对设备 Flash 的实时测量。设备另返回真实 buildId。

测试 PIN 是八个 0；固定公开测试私钥不得转入真实资金。测试数据在 `/e2e`，正常数据在 `/vault`。再次运行沿用真实历史额度，创建新会话，不清账。不自动整片擦除或恢复旧备份。

按键注入回执只代表原始电平已接收，正常去抖、松键事件和屏幕绘制随后执行。测试需要轮询实际 UI 状态或等待业务结果，不能把第一帧状态或注入回执当作操作已完成。

`prepare` 和 `smoke` 不打开/刷写设备，也不代表 USB/实体按钮验收。运行 `integration:rockey` 必须有真实设备，缺失时失败。SDK 各 Profile/双向迁移原生测试继续作为前置检查；本自动 USB 流程覆盖 22 项核心行为，完整 App、真实掉电及迁移菜单的真机门禁单独记录。

故障定位可以设置 `VLP_ROCKEY_DIAGNOSTIC_PAYMENTS=1` 仅执行 18 项付款流程，或 `VLP_ROCKEY_DIAGNOSTIC_PAYMENTS=pools` 仅执行两种费用池。这两种报告均带 `diagnosticOnly: true`，不能代替完整 22 项通过。测试状态额外返回堆/栈空间、UART 错误、外层帧丢弃数与设备异常码；关闭前采集状态只用于诊断，不改变批准或重试付款。
